#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include "pegasus/ioworker.h"
#include "pegasus/runtime.h"
#include "pegasus/uswitch.h"
#include "pegasus/util.h"
#include "pegasus/network/local.h"
#include "pegasus/network/network.h"
#include "pegasus/network/socket.h"

using namespace pegasus;

static SpinLock network_context_mutex;
static std::unordered_map<ino_t, std::weak_ptr<NetworkContext>> network_contexts;

NetworkContext::NetworkContext(USwitchContext *ucontext, int netns_fd)
    : vnetwork(std::make_shared<VirtualNetwork>(ucontext, netns_fd)) {
    IOWorker *iow = Runtime::get()->get_tm()->get_ioworker();
    if (iow) {
        factories.push_back(IOWorker::create);
    }
    factories.push_back(LinuxSocket::create);
}

NetworkContext::~NetworkContext() {

}

bool NetworkContext::create_socket(VThread *vthread, FDFilePair &out,
                                   bool allow_local, int domain, int type, int protocol) {
    bool local = allow_local && LocalSocket::support(domain, type, protocol);
    for (SocketFactory &f : factories) {
        if (f(vthread, out, local, domain, type, protocol)) {
            return true;
        }
    }
    return false;
}

std::shared_ptr<NetworkContext> NetworkContext::get_network_context(USwitchContext *ucontext, int netns_fd) {
    struct stat sbuf;
    if (fstat(netns_fd, &sbuf) == -1) {
        throw Exception("failed to get inode for netns fd: " + std::string(strerror(errno)));
    }
    ino_t inode = sbuf.st_ino;
    std::lock_guard lock(network_context_mutex);
    auto it = network_contexts.find(inode);
    if (it != network_contexts.end()) {
        std::shared_ptr<NetworkContext> nc = it->second.lock();
        if (!nc) {
            nc = std::make_shared<NetworkContext>(ucontext, netns_fd);
            it->second = nc;
            return nc;
        }
        return nc;
    }
    std::shared_ptr<NetworkContext> nc = std::make_shared<NetworkContext>(ucontext, netns_fd);
    network_contexts.emplace(inode, nc);
    return nc;
}

VirtualConnection::VirtualConnection(size_t buffer_size) {
    upstream = std::make_shared<Pipe>(buffer_size);
    downstream = std::make_shared<Pipe>(buffer_size);
}

VirtualConnection::~VirtualConnection() {
}

VirtualServer::VirtualServer(int domain_, int port_, int max_waiting_)
    : ready(false), domain(domain_), port(port_), max_waiting(max_waiting_),
      accept_wq(std::make_shared<WaitQueue>()) {
}

void VirtualServer::notify() {
    accept_wq->wake_all();
    std::shared_ptr<File> s = sock.lock();
    if (s) {
        std::unique_lock lock(s->get_mutex());
        s->notify(EPOLLIN, lock);
    }
}

std::shared_ptr<VirtualConnection> VirtualServer::get_conn() {
    //std::lock_guard lock(mutex);
    if (waiting_connections.empty()) {
        return nullptr;
    }
    auto it = waiting_connections.begin();
    std::shared_ptr<VirtualConnection> vconn = *it;
    waiting_connections.erase(it);
    return vconn;
}

bool VirtualServer::add_conn(const std::shared_ptr<VirtualConnection> &conn) {
    std::lock_guard lock(mutex);
    if (waiting_connections.size() >= (size_t)max_waiting) {
        return false;
    }
    waiting_connections.push_back(conn);
    return true;
}

VirtualNetwork::VirtualNetwork(USwitchContext *ucontext, int netns_fd) {
    struct ifaddrs *ifas = nullptr;
    ucontext->run_on_behalf_of([&] {
        if (getifaddrs(&ifas) == -1) {
            throw Exception("failed to getifaddrs: " + std::string(strerror(errno)));
        }
    });
    CleanupHelper cleanup([ifas] { freeifaddrs(ifas); });
    for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
        struct sockaddr *addr = ifa->ifa_addr;
        if (!addr) {
            continue;
        }
        if (addr->sa_family == AF_INET) {
            addr_in.emplace(((struct sockaddr_in *)addr)->sin_addr);
        } else if (addr->sa_family == AF_INET6) {
            addr_in6.emplace(((struct sockaddr_in6 *)addr)->sin6_addr);
        }
    }
    addr_in.emplace(in_addr {htonl(INADDR_LOOPBACK)} );
    addr_in6.emplace(in6addr_loopback);
}

VirtualNetwork::~VirtualNetwork() {
}

std::shared_ptr<VirtualServer> VirtualNetwork::get_ipv4_server(const struct sockaddr_in *addr) {
    //printf("connecting %x %d\n", ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));
    if (!addr_in.count(addr->sin_addr)) {
        return nullptr;
    }
    int port = ntohs(addr->sin_port);
    std::lock_guard lock(mutex);
    auto it = ipv4_servers.find(port);
    if (it == ipv4_servers.end()) {
        return nullptr;
    }
    return it->second.lock();
}

std::shared_ptr<VirtualServer> VirtualNetwork::get_ipv6_server(const struct sockaddr_in6 *addr) {
    if (!addr_in6.count(addr->sin6_addr)) {
        return nullptr;
    }
    int port = ntohs(addr->sin6_port);
    std::lock_guard lock(mutex);
    auto it = ipv6_servers.find(port);
    if (it == ipv6_servers.end()) {
        return nullptr;
    }
    return it->second.lock();
}

void VirtualNetwork::set_ipv4_server(int port, const std::shared_ptr<VirtualServer> &server) {
    std::lock_guard lock(mutex);
    //printf("set server %d\n", port);
    ipv4_servers[port] = server;
}

void VirtualNetwork::set_ipv6_server(int port, const std::shared_ptr<VirtualServer> &server) {
    std::lock_guard lock(mutex);
    ipv6_servers[port] = server;
}

void VirtualNetwork::add_server(const std::shared_ptr<VirtualServer> &server) {
    if (server->domain == AF_INET) {
        set_ipv4_server(server->port, server);
    }
    if (server->domain == AF_INET6) {
        set_ipv4_server(server->port, server);
        set_ipv6_server(server->port, server);
    }
}

std::shared_ptr<VirtualServer> VirtualNetwork::get_server(const sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        return get_ipv4_server((const sockaddr_in *)addr);
    } else if (addr->sa_family == AF_INET6) {
        return get_ipv6_server((const sockaddr_in6 *)addr);
    }
    return nullptr;
}
