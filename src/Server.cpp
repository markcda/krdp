// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "Server.h"

#include <algorithm>
#include <chrono>
#include <optional>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <QCoreApplication>
#include <QPointer>
#include <QSet>
#include <QTimer>

#include <freerdp/channels/channels.h>
#include <freerdp/freerdp.h>
#include <winpr/ssl.h>

#include "RdpConnection.h"

#include "krdp_logging.h"

using namespace KRdp;
using namespace std::chrono_literals;

namespace
{

/**
 * How long a client gets to log in before its connection is dropped.
 *
 * A client sends its credentials as part of connecting, so nothing legitimate
 * needs anywhere near this long. The limit keeps connection attempts that never
 * finish from piling up.
 */
constexpr auto loginGracePeriod = 30s;
/**
 * How many accepted connections that have not logged in yet to keep around.
 *
 * When there are more, the oldest one is dropped. Since it is always the oldest
 * that goes, a flood of connection attempts cannot keep a newly arriving client
 * from getting the chance to log in.
 */
constexpr int maxPendingLogins = 16;
/**
 * How many of those may come from a single address.
 *
 * This keeps a single host that keeps retrying from using up all of the above.
 */
constexpr int maxPendingLoginsPerAddress = 2;
/**
 * How long to wait before trying to listen again when that failed.
 */
constexpr auto relistenInterval = 2s;

/**
 * A connection that has been accepted but has not logged in yet.
 */
struct PendingLogin {
    RdpConnection *connection = nullptr;
    /// The address the connection came from, null if it could not be determined.
    QHostAddress address;
};

/**
 * Read the address of the remote end of an accepted socket.
 */
std::optional<QHostAddress> peerAddressForHandle(qintptr handle)
{
    sockaddr_storage storage;
    socklen_t length = sizeof(storage);
    if (getpeername(int(handle), reinterpret_cast<sockaddr *>(&storage), &length) != 0) {
        return std::nullopt;
    }

    switch (storage.ss_family) {
    case AF_INET:
        return QHostAddress(ntohl(reinterpret_cast<sockaddr_in *>(&storage)->sin_addr.s_addr));
    case AF_INET6:
        return QHostAddress(reinterpret_cast<sockaddr_in6 *>(&storage)->sin6_addr.s6_addr);
    default:
        return std::nullopt;
    }
}

/**
 * Remove a connection from the list of pending logins, returning whether it was
 * in there to begin with.
 */
bool removePendingLogin(QList<PendingLogin> &pendingLogins, RdpConnection *connection)
{
    auto itr = std::find_if(pendingLogins.begin(), pendingLogins.end(), [connection](const PendingLogin &pending) {
        return pending.connection == connection;
    });
    if (itr == pendingLogins.end()) {
        return false;
    }

    pendingLogins.erase(itr);
    return true;
}

}

class KRDP_NO_EXPORT Server::Private
{
public:
    std::vector<std::unique_ptr<RdpConnection>> sessions;
    rdp_settings *settings = nullptr;

    QHostAddress address = QHostAddress::LocalHost;
    quint16 port = 3389;

    QList<User> users;
    bool usePamAuthentication = false;

    bool singleConnection = true;
    // Connections that have logged in and have not closed yet. While there is at
    // least one and singleConnection is set, the server does not listen.
    QSet<RdpConnection *> loggedInConnections;
    // Accepted connections that have not logged in yet, oldest first.
    QList<PendingLogin> pendingLogins;
    // Set while the listening socket is closed because a session is in use.
    bool listeningSuspended = false;
    // Set while a retry of a failed resumeListening() is scheduled.
    bool relistenScheduled = false;
    // Consecutive failures to listen again, so a port that stays occupied does
    // not produce a warning every couple of seconds.
    int relistenFailures = 0;

    std::filesystem::path tlsCertificate;
    std::filesystem::path tlsCertificateKey;
};

Server::Server(QObject *parent)
    : QTcpServer(parent)
    , d(std::make_unique<Private>())
{
    winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);
    WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
}

Server::~Server()
{
    stop();
}

bool Server::start()
{
    if (!std::filesystem::exists(d->tlsCertificate) || !std::filesystem::exists(d->tlsCertificateKey)) {
        qCCritical(KRDP).nospace() << "A valid TLS certificate (" << QString::fromStdString(d->tlsCertificate.filename().string()) << ") and key ("
                                   << QString::fromStdString(d->tlsCertificateKey.filename().string()) << ") is required for the server to run!";
        return false;
    }

    if (!listen(d->address, d->port)) {
        // NOTE: We cannot use QTcpServer methods to get the server address and port because it won't initialize them if listen fails.
        qCCritical(KRDP) << "Unable to listen for connections on" << d->address << d->port;
        return false;
    }

    // FreeRDP3 tries to use a global instance of the settings object when
    // initializing a new peer. However, it seems to fail at actually creating a
    // global default instance. So create one here and use that.
    d->settings = freerdp_settings_new(FREERDP_SETTINGS_SERVER_MODE);

    qCDebug(KRDP) << "Listening for connections on" << serverAddress() << serverPort();
    return true;
}

void Server::stop()
{
    close();
    d->listeningSuspended = false;

    if (d->settings) {
        freerdp_settings_free(d->settings);
        d->settings = nullptr;
    }
}

QHostAddress Server::address() const
{
    return d->address;
}

void Server::setAddress(const QHostAddress &newAddress)
{
    if (newAddress == d->address) {
        return;
    }

    d->address = newAddress;
}

quint16 Server::port() const
{
    return d->port;
}

void Server::setPort(quint16 newPort)
{
    if (newPort == d->port) {
        return;
    }

    d->port = newPort;
}

QList<User> KRdp::Server::users() const
{
    return d->users;
}

void KRdp::Server::setUsers(const QList<User> &users)
{
    d->users = users;
}

void KRdp::Server::addUser(const User &user)
{
    d->users.append(user);
}

bool Server::singleConnection() const
{
    return d->singleConnection;
}

void Server::setSingleConnection(bool singleConnection)
{
    if (singleConnection == d->singleConnection) {
        return;
    }

    d->singleConnection = singleConnection;

    if (!singleConnection) {
        // Allowing multiple connections again means we should be listening, even
        // if a session is currently in use.
        resumeListening();
    } else if (!d->loggedInConnections.isEmpty()) {
        suspendListening();
    }
}

bool Server::usePAMAuthentication() const
{
    return d->usePamAuthentication;
}

void Server::setUsePAMAuthentication(bool usePAM)
{
    d->usePamAuthentication = usePAM;
}

std::filesystem::path Server::tlsCertificate() const
{
    return d->tlsCertificate;
}

void Server::setTlsCertificate(const std::filesystem::path &newTlsCertificate)
{
    if (newTlsCertificate == d->tlsCertificate) {
        return;
    }

    d->tlsCertificate = newTlsCertificate;
}

std::filesystem::path Server::tlsCertificateKey() const
{
    return d->tlsCertificateKey;
}

void Server::setTlsCertificateKey(const std::filesystem::path &newTlsCertificateKey)
{
    if (newTlsCertificateKey == d->tlsCertificateKey) {
        return;
    }

    d->tlsCertificateKey = newTlsCertificateKey;
}

void Server::suspendListening()
{
    if (!isListening()) {
        return;
    }

    // Closing the listening socket only affects connections that have not been
    // accepted yet; the sessions that are running keep their own sockets.
    close();
    d->listeningSuspended = true;
    qCInfo(KRDP) << "A client is logged in, no longer accepting connections on" << d->address << d->port;
}

void Server::resumeListening()
{
    if (!d->listeningSuspended || isListening()) {
        return;
    }

    if (!d->settings) {
        // The server was never started or has been stopped in the meantime.
        d->listeningSuspended = false;
        return;
    }

    if (listen(d->address, d->port)) {
        d->listeningSuspended = false;
        d->relistenFailures = 0;
        qCInfo(KRDP) << "Accepting connections again on" << d->address << d->port;
        return;
    }

    ++d->relistenFailures;
    if (d->relistenFailures == 1) {
        qCWarning(KRDP) << "Unable to listen for connections again on" << d->address << d->port << "-" << errorString() << "- retrying every"
                        << relistenInterval.count() << "seconds";
    } else {
        qCDebug(KRDP) << "Still unable to listen for connections again on" << d->address << d->port << "-" << errorString();
    }

    if (!d->relistenScheduled) {
        d->relistenScheduled = true;
        QTimer::singleShot(relistenInterval, this, [this]() {
            d->relistenScheduled = false;
            resumeListening();
        });
    }
}

void Server::enforcePendingLoginLimits()
{
    if (d->pendingLogins.isEmpty()) {
        return;
    }

    auto dropOldest = [this](auto &&matches, const char *reason) {
        auto itr = std::find_if(d->pendingLogins.begin(), d->pendingLogins.end(), matches);
        if (itr == d->pendingLogins.end()) {
            return false;
        }

        auto *connection = itr->connection;
        const auto address = itr->address;
        d->pendingLogins.erase(itr);

        qCDebug(KRDP) << reason << "- dropping the connection attempt from" << address;
        connection->close(RdpConnection::CloseReason::None);
        return true;
    };

    const auto address = d->pendingLogins.constLast().address;
    if (!address.isNull()) {
        auto fromSameAddress = [this, &address]() {
            return std::count_if(d->pendingLogins.cbegin(), d->pendingLogins.cend(), [&address](const PendingLogin &pending) {
                return pending.address == address;
            });
        };
        while (fromSameAddress() > maxPendingLoginsPerAddress) {
            const auto matchesAddress = [&address](const PendingLogin &pending) {
                return pending.address == address;
            };
            if (!dropOldest(matchesAddress, "Too many connections from the same address waiting to log in")) {
                break;
            }
        }
    }

    while (d->pendingLogins.size() > maxPendingLogins) {
        const auto matchesAny = [](const PendingLogin &) {
            return true;
        };
        if (!dropOldest(matchesAny, "Too many connections waiting to log in")) {
            break;
        }
    }
}

void Server::removeSession(RdpConnection *connection)
{
    auto itr = std::find_if(d->sessions.begin(), d->sessions.end(), [connection](auto &session) {
        return session.get() == connection;
    });
    if (itr == d->sessions.end()) {
        return;
    }

    // extracted before erasing: ~RdpConnection can spin a nested event loop (KScreen calls
    // from destroyed() handlers) that re-enters this vector, so destroy it once consistent again
    auto session = std::move(*itr);
    d->sessions.erase(itr);
}

void Server::incomingConnection(qintptr handle)
{
    // Needs to happen before the handle is handed over to FreeRDP.
    const auto address = peerAddressForHandle(handle);

    auto session = std::make_unique<RdpConnection>(this, handle);
    auto sessionPtr = session.get();
    // queued: signal comes from the run thread, and it keeps the erase below from destroying the sender mid-emission
    connect(
        sessionPtr,
        &RdpConnection::stateChanged,
        this,
        [this, sessionPtr](RdpConnection::State state) {
            if (state == RdpConnection::State::Activated) {
                // RDP authentication has completed by the time a connection is
                // activated, so from here on this is a client of ours.
                if (d->loggedInConnections.contains(sessionPtr)) {
                    return;
                }

                removePendingLogin(d->pendingLogins, sessionPtr);
                d->loggedInConnections.insert(sessionPtr);

                if (d->singleConnection) {
                    suspendListening();
                    // Drop what is still trying to log in as well, so it cannot
                    // interfere with the session that just started.
                    const auto pending = d->pendingLogins;
                    d->pendingLogins.clear();
                    for (const auto &entry : pending) {
                        qCDebug(KRDP) << "A client logged in - dropping the connection attempt from" << entry.address;
                        entry.connection->close(RdpConnection::CloseReason::None);
                    }
                }
                return;
            }

            if (state != RdpConnection::State::Closed) {
                return;
            }

            removePendingLogin(d->pendingLogins, sessionPtr);
            const bool wasLoggedIn = d->loggedInConnections.remove(sessionPtr);

            removeSession(sessionPtr);

            // Only once the last client is gone, and only after the connection
            // above has been destroyed, so a new one cannot arrive in the middle
            // of that.
            if (wasLoggedIn && d->loggedInConnections.isEmpty()) {
                resumeListening();
            }
        },
        Qt::QueuedConnection);
    d->sessions.push_back(std::move(session));
    d->pendingLogins.append(PendingLogin{sessionPtr, address.value_or(QHostAddress())});
    enforcePendingLoginLimits();

    // Nothing legitimate waits this long to log in, so make sure a connection
    // that never does goes away instead of lingering.
    QTimer::singleShot(loginGracePeriod, this, [this, connection = QPointer<RdpConnection>(sessionPtr)]() {
        if (!connection) {
            return;
        }
        if (!removePendingLogin(d->pendingLogins, connection)) {
            return;
        }

        const auto state = connection->state();
        if (state == RdpConnection::State::Initial || state == RdpConnection::State::Starting) {
            // The connection never got as far as starting its thread, so setting
            // it up failed. It will not report itself as closed either, so take
            // it out here rather than letting it linger.
            qCDebug(KRDP) << "Connection failed to start up - removing it";
            removeSession(connection);
            return;
        }

        qCDebug(KRDP) << "Connection did not log in within" << loginGracePeriod.count() << "seconds - dropping it";
        connection->close(RdpConnection::CloseReason::None);
    });

    Q_EMIT newConnectionCreated(sessionPtr);
}

rdp_settings *Server::rdpSettings() const
{
    return d->settings;
}

#include "moc_Server.cpp"
