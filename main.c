#include <stddef.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <linux/sockios.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/unistd.h>

#include <wlmio.h>


static int epollfd = -1;


struct fd_entry
{
  int fd;
  void (* handler)(struct fd_entry*, uint32_t events);
  void* data;
  struct fd_entry* next;
  struct fd_entry* previous;
};
static struct fd_entry* fd_entry_head = NULL;


static struct fd_entry* fd_entry_find(int fd)
{
  struct fd_entry* c = fd_entry_head;
  while(c)
  {
    if(c->fd == fd)
    { break; }

    c = c->next;
  }

  return c;
}


static void fd_entry_close(struct fd_entry* const entry)
{
  assert(entry);

  if(entry->previous)
  { entry->previous->next = entry->next; }
  else
  { fd_entry_head = entry->next; }

  if(entry->next)
  { entry->next->previous = entry->previous; }

  close(entry->fd);
  free(entry);
}


static struct fd_entry* fd_entry_add(
    int fd,
    void (* const handler)(struct fd_entry*, uint32_t events),
    void* const data,
    uint32_t events
)
{
  assert(handler);

  struct fd_entry* c = fd_entry_head;
  struct fd_entry* end = NULL;
  while(c)
  {
    if(c->next == NULL)
    { end = c; }

    c = c->next;
  }

  c = malloc(sizeof(struct fd_entry));
  c->fd = fd;
  c->handler = handler;
  c->data = data;
  c->previous = end;
  c->next = NULL;

  if(end)
  { end->next = c; }
  else
  { fd_entry_head = c; }

  struct epoll_event ev;
  ev.events = events;
  ev.data.ptr = c;
  epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);

  return c;
}


struct mb_msg
{
  int s; // socket
  uint16_t tid; // transaction identifier
  uint16_t pid; // protocol identifier
  uint8_t uid; // unit identifier
  uint8_t fc; // function code
  uint16_t len; // number of data bytes
  uint8_t data[252]; // message data
};


void mb_send_message(struct mb_msg* const msg)
{
  assert(msg);
  assert(msg->len <= 253);

  uint8_t data[260];

  memcpy(data + 0, &(uint16_t){htons(msg->tid)}, 2);
  memcpy(data + 2, &(uint16_t){htons(msg->pid)}, 2);
  memcpy(data + 4, &(uint16_t){htons(msg->len + 2)}, 2);
  memcpy(data + 6, &msg->uid, 1);
  memcpy(data + 7, &msg->fc, 1);
  memcpy(data + 8, &msg->data, msg->len);

  write(msg->s, data, 8 + msg->len);
}


void mb_generate_exception(struct mb_msg* const msg, uint8_t ex)
{
  assert(msg);

  msg->fc += 0x80;
  msg->len = 1;
  memcpy(msg->data, &ex, 1);
}


struct node
{
  struct wlmio_status status;
  struct wlmio_node_info info;
  uint16_t holding_registers[49];
  uint16_t holding_registers_length;
  struct fd_entry* timer;
  uint8_t id;
};
struct node nodes[128];


void dummy_handler(int32_t r, void* data) { }


void write_holding_register(struct node* const node, const uint16_t r, const uint16_t v)
{
  assert(node);

  if(r < sizeof(node->holding_registers) / sizeof(uint16_t))
  { return; }

  struct wlmio_register_access regw;
  char name[257];

  if(!strncmp(node->info.name, "com.widgetlords.mio.6010", 50) && r == 49)
  {
    strncpy(name, "sample_interval", sizeof(name));
    regw.type = WLMIO_REGISTER_VALUE_UINT16;
    regw.length = 1;

    memcpy(regw.value, &v, 2);
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6030", 50))
  {
    if(r >= 49 && r <= 52)
    { snprintf(name, sizeof(name), "ch%u.output", r - 48); }
    else
    { return; }

    regw.type = WLMIO_REGISTER_VALUE_UINT8;
    regw.length = 1;

    memcpy(regw.value, &v, 1);
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6040", 50))
  {
    if(r >= 54 && r <= 57)
    { snprintf(name, sizeof(name), "ch%u.mode", r - 53); }
    else
    { return; }

    regw.type = WLMIO_REGISTER_VALUE_UINT8;
    regw.length = 1;

    memcpy(regw.value, &v, 1);
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6050", 50))
  {
    regw.length = 1;

    if(r >= 49 && r <= 52)
    {
      snprintf(name, sizeof(name), "ch%u.output", r - 48);

      regw.type = WLMIO_REGISTER_VALUE_UINT16;

      memcpy(regw.value, &v, 2);
    }
    else if(r >= 53 && r <= 56)
    {
      snprintf(name, sizeof(name), "ch%u.mode", r - 52);

      regw.type = WLMIO_REGISTER_VALUE_UINT8;

      memcpy(regw.value, &v, 1);
    }
    else
    { return; }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6060", 50))
  {
    regw.length = 1;

    if(r == 49)
    {
      strncpy(name, "sample_interval", sizeof(name));

      regw.type = WLMIO_REGISTER_VALUE_UINT16;

      memcpy(regw.value, &v, 2);
    }
    else if(r >= 58 && r <= 69)
    {
      if(r <= 61)
      { snprintf(name, sizeof(name), "ch%u.mode", r - 57); }
      else if(r <= 65)
      { snprintf(name, sizeof(name), "ch%u.bias", r - 61); }
      else if(r <= 69)
      { snprintf(name, sizeof(name), "ch%u.polarity", r - 65); }

      regw.type = WLMIO_REGISTER_VALUE_UINT8;

      memcpy(regw.value, &v, 1);
    }
    else
    { return; }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6070", 50))
  {
    if(r >= 49 && r <= 52)
    { snprintf(name, sizeof(name), "ch%u.output", r - 48); }
    else
    { return; }

    regw.type = WLMIO_REGISTER_VALUE_UINT16;
    regw.length = 1;

    memcpy(regw.value, &v, 2);
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6080", 50))
  {
    regw.length = 1;

    if(r == 49 || (r >= 65 && r <= 80))
    {
      if(r == 49)
      { strncpy(name, "sample_interval", sizeof(name)); }
      else if(r >= 65 && r <= 72)
      { snprintf(name, sizeof(name), "ch%u.beta", r - 64); }
      else if(r >= 73 && r <= 80)
      { snprintf(name, sizeof(name), "ch%u.t0", r - 72); }

      regw.type = WLMIO_REGISTER_VALUE_UINT16;

      memcpy(regw.value, &v, 2);
    }
    else if(r >= 57 && r <= 64)
    {
      snprintf(name, sizeof(name), "ch%u.enabled", r - 56);

      regw.type = WLMIO_REGISTER_VALUE_UINT8;

      memcpy(regw.value, &v, 1);
    }
    else
    { return; }
  }
  else
  { return; }

  wlmio_register_access(node->id, name, &regw, NULL, dummy_handler, NULL);
}


struct register_cache
{
  struct wlmio_register_access reg;
  char name[257];
};
struct register_cache cache;


int8_t read_holding_register(const struct node* const node, const uint16_t reg, void* const dst)
{
  assert(node);
  assert(reg < node->holding_registers_length);
  assert(dst);

  if(reg < sizeof(node->holding_registers) / sizeof(uint16_t))
  {
    memcpy(dst, &(uint16_t){htons(node->holding_registers[reg])}, 2);
    return 0;
  }

  char name[257];
  struct wlmio_register_access regr;
  uint16_t v = 0;
  int32_t r;

  if(!strncmp(node->info.name, "com.widgetlords.mio.6010", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "sample_interval", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg >= 50 && reg <= 55)
    {
      if(strcmp(cache.name, "input"))
      {
        strncpy(cache.name, "input", sizeof(cache.name));
        cache.name[sizeof(cache.name) - 1] = '\0';
        r = wlmio_register_access_sync(node->id, "input", NULL, &cache.reg);
        if(r < 0 || cache.reg.type != WLMIO_REGISTER_VALUE_UINT16)
        { return -1; }
      }

      memcpy(&v, cache.reg.value + (reg - 50) * 2, 2);
    }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6030", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "ch1.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 50)
    {
      r = wlmio_register_access_sync(node->id, "ch2.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 51)
    {
      r = wlmio_register_access_sync(node->id, "ch3.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 52)
    {
      r = wlmio_register_access_sync(node->id, "ch4.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6040", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "sample_interval", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 50)
    {
      r = wlmio_register_access_sync(node->id, "ch1.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 51)
    {
      r = wlmio_register_access_sync(node->id, "ch2.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 52)
    {
      r = wlmio_register_access_sync(node->id, "ch3.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 53)
    {
      r = wlmio_register_access_sync(node->id, "ch4.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 54)
    {
      r = wlmio_register_access_sync(node->id, "ch1.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 55)
    {
      r = wlmio_register_access_sync(node->id, "ch2.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 56)
    {
      r = wlmio_register_access_sync(node->id, "ch3.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 57)
    {
      r = wlmio_register_access_sync(node->id, "ch4.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 58)
    {
      r = wlmio_register_access_sync(node->id, "ch1.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 59)
    {
      r = wlmio_register_access_sync(node->id, "ch2.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 60)
    {
      r = wlmio_register_access_sync(node->id, "ch3.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 61)
    {
      r = wlmio_register_access_sync(node->id, "ch4.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6050", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "ch1.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 50)
    {
      r = wlmio_register_access_sync(node->id, "ch2.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 51)
    {
      r = wlmio_register_access_sync(node->id, "ch3.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 52)
    {
      r = wlmio_register_access_sync(node->id, "ch4.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 53)
    {
      r = wlmio_register_access_sync(node->id, "ch1.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 54)
    {
      r = wlmio_register_access_sync(node->id, "ch2.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 55)
    {
      r = wlmio_register_access_sync(node->id, "ch3.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 56)
    {
      r = wlmio_register_access_sync(node->id, "ch4.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6060", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "sample_interval", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 50 || reg == 51)
    {
      if(strcmp(cache.name, "ch1.input"))
      {
        strncpy(cache.name, "ch1.input", sizeof(cache.name));
        cache.name[sizeof(cache.name) - 1] = '\0';
        r = wlmio_register_access_sync(node->id, cache.name, NULL, &cache.reg);
        if(r < 0 || cache.reg.type != WLMIO_REGISTER_VALUE_UINT32)
        { return -1; }
      }

      memcpy(&v, cache.reg.value + (reg & 1) * 2, 2);
    }
    else if(reg == 52 || reg == 53)
    {
      if(strcmp(cache.name, "ch2.input"))
      {
        strncpy(cache.name, "ch2.input", sizeof(cache.name));
        cache.name[sizeof(cache.name) - 1] = '\0';
        r = wlmio_register_access_sync(node->id, cache.name, NULL, &cache.reg);
        if(r < 0 || cache.reg.type != WLMIO_REGISTER_VALUE_UINT32)
        { return -1; }
      }

      memcpy(&v, cache.reg.value + (reg & 1) * 2, 2);
    }
    else if(reg == 54 || reg == 55)
    {
      if(strcmp(cache.name, "ch3.input"))
      {
        strncpy(cache.name, "ch3.input", sizeof(cache.name));
        cache.name[sizeof(cache.name) - 1] = '\0';
        r = wlmio_register_access_sync(node->id, cache.name, NULL, &cache.reg);
        if(r < 0 || cache.reg.type != WLMIO_REGISTER_VALUE_UINT32)
        { return -1; }
      }

      memcpy(&v, cache.reg.value + (reg & 1) * 2, 2);
    }
    else if(reg == 56 || reg == 57)
    {
      if(strcmp(cache.name, "ch4.input"))
      {
        strncpy(cache.name, "ch4.input", sizeof(cache.name));
        cache.name[sizeof(cache.name) - 1] = '\0';
        r = wlmio_register_access_sync(node->id, cache.name, NULL, &cache.reg);
        if(r < 0 || cache.reg.type != WLMIO_REGISTER_VALUE_UINT32)
        { return -1; }
      }

      memcpy(&v, cache.reg.value + (reg & 1) * 2, 2);
    }
    else if(reg == 58)
    {
      r = wlmio_register_access_sync(node->id, "ch1.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 59)
    {
      r = wlmio_register_access_sync(node->id, "ch2.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 60)
    {
      r = wlmio_register_access_sync(node->id, "ch3.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 61)
    {
      r = wlmio_register_access_sync(node->id, "ch4.mode", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 62)
    {
      r = wlmio_register_access_sync(node->id, "ch1.bias", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 63)
    {
      r = wlmio_register_access_sync(node->id, "ch2.bias", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 64)
    {
      r = wlmio_register_access_sync(node->id, "ch3.bias", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 65)
    {
      r = wlmio_register_access_sync(node->id, "ch4.bias", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 66)
    {
      r = wlmio_register_access_sync(node->id, "ch1.polarity", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 67)
    {
      r = wlmio_register_access_sync(node->id, "ch2.polarity", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 68)
    {
      r = wlmio_register_access_sync(node->id, "ch3.polarity", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 69)
    {
      r = wlmio_register_access_sync(node->id, "ch4.polarity", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6070", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "ch1.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 50)
    {
      r = wlmio_register_access_sync(node->id, "ch2.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 51)
    {
      r = wlmio_register_access_sync(node->id, "ch3.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 52)
    {
      r = wlmio_register_access_sync(node->id, "ch4.output", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
  }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6080", 50))
  {
    if(reg == 49)
    {
      r = wlmio_register_access_sync(node->id, "sample_interval", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 50)
    {
      r = wlmio_register_access_sync(node->id, "ch1.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 51)
    {
      r = wlmio_register_access_sync(node->id, "ch2.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 52)
    {
      r = wlmio_register_access_sync(node->id, "ch3.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 53)
    {
      r = wlmio_register_access_sync(node->id, "ch4.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 54)
    {
      r = wlmio_register_access_sync(node->id, "ch5.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 55)
    {
      r = wlmio_register_access_sync(node->id, "ch6.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 56)
    {
      r = wlmio_register_access_sync(node->id, "ch7.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 57)
    {
      r = wlmio_register_access_sync(node->id, "ch8.input", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 58)
    {
      r = wlmio_register_access_sync(node->id, "ch1.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 59)
    {
      r = wlmio_register_access_sync(node->id, "ch2.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 60)
    {
      r = wlmio_register_access_sync(node->id, "ch3.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 61)
    {
      r = wlmio_register_access_sync(node->id, "ch4.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 62)
    {
      r = wlmio_register_access_sync(node->id, "ch5.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 63)
    {
      r = wlmio_register_access_sync(node->id, "ch6.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 64)
    {
      r = wlmio_register_access_sync(node->id, "ch7.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 65)
    {
      r = wlmio_register_access_sync(node->id, "ch8.enabled", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT8)
      { return -1; }
      memcpy(&v, regr.value, 1);
    }
    else if(reg == 66)
    {
      r = wlmio_register_access_sync(node->id, "ch1.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 67)
    {
      r = wlmio_register_access_sync(node->id, "ch2.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 68)
    {
      r = wlmio_register_access_sync(node->id, "ch3.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 69)
    {
      r = wlmio_register_access_sync(node->id, "ch4.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 70)
    {
      r = wlmio_register_access_sync(node->id, "ch5.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 71)
    {
      r = wlmio_register_access_sync(node->id, "ch6.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 72)
    {
      r = wlmio_register_access_sync(node->id, "ch7.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 73)
    {
      r = wlmio_register_access_sync(node->id, "ch8.beta", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 74)
    {
      r = wlmio_register_access_sync(node->id, "ch1.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 75)
    {
      r = wlmio_register_access_sync(node->id, "ch2.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 76)
    {
      r = wlmio_register_access_sync(node->id, "ch3.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 77)
    {
      r = wlmio_register_access_sync(node->id, "ch4.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 78)
    {
      r = wlmio_register_access_sync(node->id, "ch5.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 79)
    {
      r = wlmio_register_access_sync(node->id, "ch6.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 80)
    {
      r = wlmio_register_access_sync(node->id, "ch7.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 81)
    {
      r = wlmio_register_access_sync(node->id, "ch8.t0", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 82)
    {
      r = wlmio_register_access_sync(node->id, "ch1.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 83)
    {
      r = wlmio_register_access_sync(node->id, "ch2.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 84)
    {
      r = wlmio_register_access_sync(node->id, "ch3.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 85)
    {
      r = wlmio_register_access_sync(node->id, "ch4.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 86)
    {
      r = wlmio_register_access_sync(node->id, "ch5.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 87)
    {
      r = wlmio_register_access_sync(node->id, "ch6.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 88)
    {
      r = wlmio_register_access_sync(node->id, "ch7.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
    else if(reg == 89)
    {
      r = wlmio_register_access_sync(node->id, "ch8.counts", NULL, &regr);
      if(r < 0 || regr.type != WLMIO_REGISTER_VALUE_UINT16)
      { return -1; }
      memcpy(&v, regr.value, 2);
    }
  }

  v = htons(v);
  memcpy(dst, &v, 2);

  return 0;
}


void modbus_handler(struct mb_msg* const msg)
{
  assert(msg);

  cache.name[0] = '\0';

  if(msg->uid == 255) // Gateway itself
  { mb_generate_exception(msg, 0x01); }
  else if(msg->uid >= 128)
  { mb_generate_exception(msg, 0x0A); }
  else if(nodes[msg->uid].status.mode == WLMIO_MODE_OFFLINE)
  { mb_generate_exception(msg, 0x0B); }
  else if(msg->fc == 3) // read holding registers
  {
    uint16_t s, n;
    memcpy(&s, msg->data + 0, 2);
    memcpy(&n, msg->data + 2, 2);
    s = ntohs(s);
    n = ntohs(n);

    if(s + n > nodes[msg->uid].holding_registers_length)
    {
      mb_generate_exception(msg, 0x02);
      goto respond;
    }

    msg->len = n * 2 + 1;
    msg->data[0] = n * 2;

    for(uint_fast8_t i = 0; i < n; i += 1)
    { 
      int8_t r = read_holding_register(&nodes[msg->uid], s + i, msg->data + 1 + i * 2);
      if(r < 0)
      {
        mb_generate_exception(msg, 0x04);
        goto respond;
      }
    }
  }
  else if(msg->fc == 6) // write single register
  {
    if(msg->len != 4)
    {
      mb_generate_exception(msg, 0x03);
      goto respond;
    }

    uint16_t a, v;
    memcpy(&a, msg->data + 0, 2);
    memcpy(&v, msg->data + 2, 2);

    a = ntohs(a);
    v = ntohs(v);

    if(a >= nodes[msg->uid].holding_registers_length)
    {
      mb_generate_exception(msg, 0x02);
      goto respond;
    }

    write_holding_register(&nodes[msg->uid], a, v);
  }
  else if(msg->fc == 16) // write multiple registers
  {
    if(msg->len < 7)
    {
      mb_generate_exception(msg, 0x03);
      goto respond;
    }

    uint16_t s, n;
    uint8_t b;
    memcpy(&s, msg->data + 0, 2);
    memcpy(&n, msg->data + 2, 2);
    memcpy(&b, msg->data + 4, 1);
    s = ntohs(s);
    n = ntohs(n);

    if(s + n > nodes[msg->uid].holding_registers_length)
    {
      mb_generate_exception(msg, 0x02);
      goto respond;
    }

    if(n == 0 || n > 123 || b != n * 2)
    {
      mb_generate_exception(msg, 0x03);
      goto respond;
    }

    for(uint_fast8_t i = 0; i < n; i += 1)
    {
      uint16_t v;
      memcpy(&v, msg->data + 5 + i * 2, 2);
      v = ntohs(v);
      write_holding_register(&nodes[msg->uid], s + i, v);
    }

    msg->len = 4;
  }
  else
  { mb_generate_exception(msg, 0x01); }

respond:
  mb_send_message(msg);
  free(msg);
}


void conn_handler(struct fd_entry* const entry, uint32_t events)
{
  if(events & EPOLLERR || events & EPOLLHUP)
  { goto close; }

  uint8_t data[256];
  int r = read(entry->fd, data, 7);
  if(r < 7)
  { goto close; }

  struct mb_msg* const msg = malloc(sizeof(struct mb_msg));

  msg->s = entry->fd;

  memcpy(&msg->tid, data, 2);
  msg->tid = ntohs(msg->tid);

  memcpy(&msg->pid, data + 2, 2);
  msg->pid = ntohs(msg->pid);

  memcpy(&msg->len, data + 4, 2);
  msg->len = ntohs(msg->len) - 2;

  memcpy(&msg->uid, data + 6, 1);

  r = read(entry->fd, data, msg->len + 1);
  if(r < msg->len + 1)
  { goto close; }

  memcpy(&msg->fc, data, 1);
  memcpy(&msg->data, data + 1, msg->len);

  modbus_handler(msg);

  goto exit;

close:
  fd_entry_close(entry);

exit:
  return;
}


void tcp_socket_handler(struct fd_entry* const entry, uint32_t events)
{
  int s = accept(entry->fd, NULL, NULL);

  fd_entry_add(s, conn_handler, NULL, EPOLLIN);
}


void wlmio_handler(struct fd_entry* const entry, uint32_t events)
{
  wlmio_tick();
}


void info_callback(int32_t r, void* p)
{
  const uint8_t node_id = (intptr_t)p;

  struct node* const node = &nodes[node_id];

  memcpy(node->holding_registers + 5, &node->info.protocol_version, 2);
  memcpy(node->holding_registers + 6, &node->info.hardware_version, 2);
  memcpy(node->holding_registers + 7, &node->info.software_version, 2);

  memcpy(node->holding_registers + 8, &node->info.software_vcs_revision_id, 8);
  
  memcpy(node->holding_registers + 12, node->info.unique_id, 16); 

  memcpy(node->holding_registers + 20, node->info.name, 50); 

  memcpy(node->holding_registers + 45, &node->info.software_image_crc, 8);

  if(!strncmp(node->info.name, "com.widgetlords.mio.6010", 50))
  { node->holding_registers_length += 7; }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6030", 50))
  { node->holding_registers_length += 4; }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6040", 50))
  { node->holding_registers_length += 13; }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6050", 50))
  { node->holding_registers_length += 8; }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6060", 50))
  { node->holding_registers_length += 21; }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6070", 50))
  { node->holding_registers_length += 4; }
  else if(!strncmp(node->info.name, "com.widgetlords.mio.6080", 50))
  { node->holding_registers_length += 41; }
}


void status_callback(const uint8_t node_id, const struct wlmio_status* const old_status, const struct wlmio_status* new_status)
{
  nodes[node_id].status = *new_status;

  nodes[node_id].holding_registers[0] = new_status->uptime;
  nodes[node_id].holding_registers[1] = new_status->uptime >> 16;
  nodes[node_id].holding_registers[2] = new_status->health;
  nodes[node_id].holding_registers[3] = new_status->mode;
  nodes[node_id].holding_registers[4] = new_status->vendor_status;

  if((old_status->mode == 7 && new_status->mode != 7) || (new_status->uptime < old_status->uptime && new_status->uptime > 0))
  {
    if(nodes[node_id].timer)
    {
      fd_entry_close(nodes[node_id].timer);
      nodes[node_id].timer = NULL;
    }

    uint8_t len = sizeof(nodes[node_id].holding_registers) / sizeof(uint16_t);
    nodes[node_id].holding_registers_length = len;

    for(uint_fast8_t i = 5; i < len; i += 1)
    { nodes[node_id].holding_registers[i] = 0; }

    int32_t r = wlmio_get_node_info(node_id, &nodes[node_id].info, info_callback, (void*)(intptr_t)node_id);
  }
}


int main(int argc, char** argv)
{
  for(uint_fast8_t i = 0; i < 128; i += 1)
  {
    nodes[i].id = i;
    nodes[i].status.mode = WLMIO_MODE_OFFLINE;
    nodes[i].timer = NULL;
  }

  int r = wlmio_init();
  if(r < 0)
  {
    perror("Failed to initialize libwlmio");
    exit(1);
  }
  wlmio_set_status_callback(status_callback);

  epollfd = epoll_create1(0);
  if(epollfd < 0)
  { return -1; }
  
  fd_entry_add(wlmio_get_epoll_fd(), wlmio_handler, NULL, EPOLLIN);

  int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

  if(setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
  { 
    perror("setsockopt(SO_REUSEADDR) failed");
    exit(1);
  }

  uint16_t port = 502;

  if(argc > 1)
  {
    char* endptr;
	  errno = 0;
	  port = strtol(argv[1], &endptr, 0);
	  if(errno == ERANGE || errno == EINVAL || argv[1] == endptr)
	  {
		  fprintf(stderr, "Invalid port number\n");
		  return EXIT_FAILURE;
	  }
  }

  struct sockaddr_in addr = 
  {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr = { INADDR_ANY }
  };
  r = bind(tcp_socket, (const struct sockaddr*)&addr, sizeof(addr));
  if(r < 0)
  {
    perror("Failed to bind socket");
    exit(EXIT_FAILURE);
  }

  r = listen(tcp_socket, 32);

  fd_entry_add(tcp_socket, tcp_socket_handler, NULL, EPOLLIN);

  while(1)
  {
    struct epoll_event ev;
    int32_t r = epoll_wait(epollfd, &ev, 1, -1);
    if(r <= 0)
    { continue; }

    struct fd_entry* entry = ev.data.ptr;
    entry->handler(entry, ev.events);
  }

  return 0;
}

