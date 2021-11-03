#include <iostream>
#include <atomic>
#include <ctime>
#include <unordered_map>
#include <fstream>
#include <regex>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "eco.hpp"
#include "eco_event.hpp"

typedef struct eco_addrinfo {
  std::string v4;
  std::string v6;
  uint64_t v4_ttl;
  uint64_t v6_ttl;
}eco_addrinfo_t;

typedef enum {
  ECO_QR_FAILED = 0,
  ECO_QR_V4 = 1,
  ECO_QR_V6 = 2,
}eco_dns_query_t;

typedef enum {
  ECO_QT_IPV4  = 0x01,
  ECO_QT_CNAME = 0x05,
  ECO_QT_IPV6  = 0x1C,
}eco_dns_qtype_t;

static inline uint32_t get_time() {
  struct timeval ts;
  gettimeofday(&ts, nullptr);
  return ts.tv_sec;
}

static inline uint32_t read_int2(char ptr[2]) {
  return ((uint8_t)ptr[0] << 8) | ((uint8_t)ptr[1]);
}

static inline uint32_t read_int4(char *ptr) {
  return (((uint8_t)ptr[0]) << 24) | (((uint8_t)ptr[1]) << 16) | (((uint8_t)ptr[2]) << 8) | ((uint8_t)ptr[3]);
}

static std::string dns_server_ip("8.8.8.8");

void eco::eco_init_dns(const char* ip) {
  srand(clock());
  dns_server_ip = std::string(ip);
}

std::atomic_flag lock = ATOMIC_FLAG_INIT;

#define __ECO_DNS_LOCK__    while (lock.test_and_set(std::memory_order_acquire)){};
#define __ECO_DNS_UNLOCK__  lock.clear(std::memory_order_release);

static std::unordered_map<std::string, eco_addrinfo_t*> resolves;

void eco::eco_load_hosts() {
  FILE *fp = fopen("/etc/hosts", "r");
  if (!fp)
    return ;

  fseek(fp, 0, SEEK_END);
  int bsize = ftell(fp);
  char buffer[bsize];
  fseek(fp, 0, SEEK_SET);
  fread(buffer, bsize, 1, fp);
  fclose(fp);

  // std::smatch item;
  std::smatch item;
  std::string text(buffer);
  std::regex pattern("[	 ]*([\\w.:]+[:.][\\w]+)[	 ]+(.+)");

  __ECO_DNS_LOCK__
  while (std::regex_search(text, item, pattern)) {
    // std::cout << '[' << item[1] << ']'  << " " << '[' << item[2] << ']' << std::endl;
    eco_addrinfo_t* addrinfo = nullptr;
    if (resolves.count(item[2].str()) == 1)
    {
      addrinfo = resolves[item[2].str()];
    }
    else
    {
      addrinfo = new eco_addrinfo_t;
      addrinfo->v4.clear();
      addrinfo->v6.clear();
      addrinfo->v4_ttl = 0;
      addrinfo->v6_ttl = 0;
      resolves[item[2].str()] = addrinfo;
    }
    struct in_addr addr_v4 = {};
    struct in6_addr addr_v6 = {};
    if (inet_pton(AF_INET, item[1].str().c_str(), &addr_v4) == 1)        /* 合法的IPv4 */
    {
      addrinfo->v4 = item[1].str();
      addrinfo->v4_ttl = LONG_MAX;
    }
    else if(inet_pton(AF_INET6, item[1].str().c_str(), &addr_v6) == 1)   /* 合法的IPv6 */
    {
      addrinfo->v6 = item[1].str();
      addrinfo->v6_ttl = LONG_MAX;
    }
    /* update */
    text = item.suffix().str();
  }
  __ECO_DNS_UNLOCK__

  // for (auto item = resolves.begin(); item != resolves.end(); item++) {
  //   std::cout << '[' << item->first << ']';
  //   if (item->second->v4_ttl > 0) {
  //     std::cout << ", v4 = [" << item->second->v4 << ']';
  //   }
  //   if (item->second->v6_ttl > 0) {
  //     std::cout << ", v6 = [" << item->second->v6 << ']';
  //   }
  //   std::cout << std::endl;
  // }

}

static inline int eco_send_request(int fd, const char* domain, eco_dns_query_t version)
{
  int rid = rand() % 65535 + 1;
  char query_header[12] = {
    // thread id
    static_cast<char>((rid >> 8) & 0xff), 
    static_cast<char>(rid & 0xff),
    // Flags
    0x01, 0x00,
    // A and Q Flags
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  // end
  const char query_end[4] = {0x00, version == ECO_QR_V6 ? (char)0x1c : (char)0x01, 0x00, 0x01};

  std::string q = domain;
  std::string query_body;
  for (;;)
  {
    std::size_t pos = q.find('.', 0);
    if (pos == std::string::npos) {
      query_body += static_cast<uint8_t>(q.length() & 0xff);
      query_body += q;
      break;
    }
    std::string sub = q.substr(0, pos);
    query_body += static_cast<uint8_t>(sub.length() & 0xff);
    query_body += sub;
    q = q.substr(pos + 1, q.length() - pos - 1);
  }

  /* concat data. */
  size_t qlen = 12 + 4 + query_body.size() + 1;
  char query[qlen];
  bzero(query, qlen);
  char *qptr = query;
  memcpy(qptr, query_header, 12);
  qptr += 12;
  memcpy(qptr, query_body.c_str(), query_body.size() + 1);
  qptr += query_body.size() + 1;
  memcpy(qptr, query_end, 4);
  /* Send */
  return write(fd, query, qlen);
}

static inline int eco_recv_response(int fd, std::string *tip, int *ttl, eco_ip_t *version)
{
  int ip_ttl = -1;
  char *ip_ptr = nullptr;
  eco_ip_t ip_ver = ECO_FAIL;

  int bsize = 8192;
  char buffer[bsize];
  int rsize = read(fd, buffer, bsize);
  if (rsize <= 12)
    return 0;

  /* check Answer */
  char *ptr = buffer + 6;
  int answer = (*ptr << 8) + (*(ptr - 1));
  if (answer < 1)
    return 0;

  /* skip query */
  ptr += 6;
  while (*ptr != '\x00')
    ptr += (*ptr) + 1;

  /* skip `Type` And `class` */
  ptr += 5;

  /* parse IP From RDATA */
  while (ptr - buffer < rsize) { 
    ptr+=2;
    int atype = read_int2(ptr);
    ptr+=4;
    // ptr+=2;
    // int classin = read_int2(ptr);
    // ptr+=2;
    int32_t ttl = read_int4(ptr);
    ptr+=4;
    int dlen = read_int2(ptr);
    ptr+=2;
    if (atype == ECO_QT_IPV4)
    {
      if (!ip_ptr)
      {
        ip_ttl = ttl;
        ip_ptr = ptr;
        ip_ver = ECO_IPV4;
      }
      else if (ttl > ip_ttl)
      {
        ip_ttl = ttl;
        ip_ptr = ptr;
        ip_ver = ECO_IPV4;
      }
      // printf("%d.%d.%d.%d\n", (uint8_t)*ptr, (uint8_t)*(ptr+1), (uint8_t)*(ptr+2), (uint8_t)*(ptr+3));
    }
    else if (atype == ECO_QT_IPV6)
    {
      if (!ip_ptr)
      {
        ip_ttl = ttl;
        ip_ptr = ptr;
        ip_ver = ECO_IPV6;
      }
      else if (ttl > ip_ttl)
      {
        ip_ttl = ttl;
        ip_ptr = ptr;
        ip_ver = ECO_IPV6;
      }
      // printf("%04x::%04x::%04x::%04x::%04x::%04x::%04x::%04x\n",
      //     read_int2(ptr),
      //     read_int2(ptr+2),
      //     read_int2(ptr+4),
      //     read_int2(ptr+6),
      //     read_int2(ptr+8),
      //     read_int2(ptr+10),
      //     read_int2(ptr+12),
      //     read_int2(ptr+14)
      // );
    }
    ptr+=dlen;
  }
  /* 如果不存在IP */
  if (!ip_ptr)
    return 0;

  *version = ip_ver;
  *ttl = ip_ttl;

  if (ip_ver == ECO_IPV4) {
    char buffer[16];
    bzero(buffer, 16);
    snprintf(buffer, 16, "%d.%d.%d.%d",
      (uint8_t)*(ip_ptr),
      (uint8_t)*(ip_ptr + 1),
      (uint8_t)*(ip_ptr + 2),
      (uint8_t)*(ip_ptr + 3)
    );
    *tip = std::string(buffer, strlen(buffer));
  }

  if (ip_ver == ECO_IPV6) {
    char buffer[40];
    bzero(buffer, 40);
    snprintf(buffer, 40, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
      read_int2(ip_ptr),
      read_int2(ip_ptr + 2),
      read_int2(ip_ptr + 4),
      read_int2(ip_ptr + 6),
      read_int2(ip_ptr + 8),
      read_int2(ip_ptr + 10),
      read_int2(ip_ptr + 12),
      read_int2(ip_ptr + 14)
    );
    *tip = std::string(buffer, 40);
  }
  return rsize;
}

static inline int eco_internal_dns_query(const char* domain, char **ip, eco_dns_query_t version)
{
  eco_addrinfo_t* addrinfo = nullptr;
  __ECO_DNS_LOCK__
  if (resolves.count(domain) == 1)
  {
    addrinfo = resolves[domain];
    if (version == ECO_QR_V4 and addrinfo->v4_ttl >= get_time())
    {
      // printf("查表 IPv4 = %s\n", addrinfo->v4.c_str());
      *ip = new char[addrinfo->v4.length()];
      strncpy((char*)*ip, addrinfo->v4.c_str(), addrinfo->v4.length());
      __ECO_DNS_UNLOCK__
      return 0;
    }
    else if(version == ECO_QR_V6 and addrinfo->v6_ttl >= get_time())
    {
      // printf("查表 IPv6 = %s\n", addrinfo->v6.c_str());
      *ip = new char[addrinfo->v6.length()];
      strncpy((char*)*ip, addrinfo->v6.c_str(), addrinfo->v6.length());
      __ECO_DNS_UNLOCK__
      return 0;
    }
  }
  else
  {
    addrinfo = new eco_addrinfo_t;
    addrinfo->v4_ttl = 0;
    addrinfo->v6_ttl = 0;
    addrinfo->v4.clear();
    addrinfo->v6.clear();
    resolves.insert(std::pair<std::string, eco_addrinfo_t*>(domain, addrinfo));
  }
  __ECO_DNS_UNLOCK__

  int fd = eco::eco_socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  
  struct sockaddr_in6 server;
  server.sin6_family = AF_INET6;
  server.sin6_port = htons(53);
  /* Only use port 53 */
  if ((inet_pton(AF_INET6, dns_server_ip.c_str(), &server.sin6_addr)) != 1 and inet_pton(AF_INET6, (std::string("::ffff:") + dns_server_ip).c_str(), &server.sin6_addr) != 1)
    eco_abort(strerror(errno));

  int ret = connect(fd, (const struct sockaddr *)&server, sizeof(server));
  if (ret < 0)
    eco_abort(strerror(errno));

  int ttl;
  eco_ip_t ipver;
  std::string tip;
  tip.clear();

  std::shared_ptr<bool> over = std::make_shared<bool>(false);
  eco::eco_fork([over, fd, domain, version]{
    while(!*over)
    {
      eco_send_request(fd, domain, version);
      eco::eco_sleep(10);
    }
    close(fd);
  });

  ret = eco_recv_response(fd, &tip, &ttl, &ipver);
  *over = true;
  if (ret <= 0)
    return -1;

  __ECO_DNS_LOCK__
  if (ipver == ECO_IPV4)
  {
    addrinfo->v4 = tip;
    addrinfo->v4_ttl = get_time() + static_cast<uint64_t>(ttl);
    *ip = new char[addrinfo->v4.length()];
    strncpy((char*)*ip, addrinfo->v4.c_str(), addrinfo->v4.length());
  }
  else if (ipver == ECO_IPV6)
  {
    addrinfo->v6 = tip;
    addrinfo->v6_ttl = get_time() + static_cast<uint64_t>(ttl);
    *ip = new char[addrinfo->v6.length()];
    strncpy((char*)*ip, addrinfo->v6.c_str(), addrinfo->v6.length());
  }
  __ECO_DNS_UNLOCK__
  return 0;
}

eco_ip_t eco::eco_dns_query4(const char* domain, char **ip)
{
  *ip = nullptr;

  if (!domain)
    return ECO_FAIL;

  if (eco_internal_dns_query(domain, ip, ECO_QR_V4))
    return ECO_FAIL;

  return ECO_IPV4;
}

eco_ip_t eco::eco_dns_query6(const char* domain, char **ip)
{
  *ip = nullptr;

  if (!domain)
    return ECO_FAIL;

  if (eco_internal_dns_query(domain, ip, ECO_QR_V6))
    return ECO_FAIL;

  return ECO_IPV6;
}

eco_ip_t eco::eco_dns_query(const char* domain, char **ip)
{

  *ip = nullptr;

  if (!eco_internal_dns_query(domain, ip, ECO_QR_V4))
    return ECO_IPV4;

  if (!eco_internal_dns_query(domain, ip, ECO_QR_V6))
    return ECO_IPV6;

  return ECO_FAIL;

}
