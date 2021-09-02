#ifndef __JTAG_TCP2_H__
#define __JTAG_TCP2_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif
#include <string.h>

#define DRSCAN 0
#define IRSCAN 1

#define JTAG_TCP2_CMD_RUNTEST 1
#define JTAG_TCP2_CMD_RESET   2
#define JTAG_TCP2_CMD_IDLE    3
#define JTAG_TCP2_CMD_IRSCAN  4
#define JTAG_TCP2_CMD_DRSCAN  5
#define JTAG_TCP2_CMD_CHAIN   6
#define JTAG_TCP2_CMD_FLUSH   7
#define JTAG_TCP2_CMD_LOCK    8
#define JTAG_TCP2_CMD_RELEASE 9
#define JTAG_TCP2_CMD_IRSCAN_BUFFERED  10
#define JTAG_TCP2_CMD_DRSCAN_BUFFERED  11

typedef struct jtag_chain_cfg_struct_t {
  uint32_t ir_chain_length;
  uint32_t ir_tap_pos;
  uint32_t ir_tap_length;
  uint32_t chain_taps;
  uint32_t chain_tap_pos;
} jtag_chain_cfg_t;

static int jtag_tcp2_init(int *pclient_socket, int port, const char *addr){
  *pclient_socket = 0;
  //---- Create the socket. The three arguments are: ----//
	// 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) //
	int client_socket = socket(PF_INET, SOCK_STREAM, 0);
  printf("client_socket=%d\n",client_socket);
	int flag = 1;
  setsockopt( client_socket,  // socket affected
              IPPROTO_TCP,    // set option at TCP level
              TCP_NODELAY,    // name of option
              (char *) &flag, // the cast is historical cruft
              sizeof(int)     // length of option value
  );

	//---- Configure settings of the server address struct ----//
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr(addr);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	//---- Connect the socket to the server using the address struct ----//
	socklen_t addr_size = sizeof serverAddr;
	if(connect(client_socket, (struct sockaddr *) &serverAddr, addr_size)){
		return -1;
	}
  *pclient_socket = client_socket;
  return 0;
}

static int jtag_tcp2_reset(int client_socket){
  uint32_t txBuffer[1];
  txBuffer[0] = JTAG_TCP2_CMD_RESET;
	if(send(client_socket,(char*)txBuffer,sizeof(txBuffer),0) <= 0){
		return -1;
  }

  return 0;
}

static int jtag_tcp2_scan_cmd(int client_socket, bool ir_scan, uint8_t *buffer, int scan_size, bool buffered){
  uint32_t txBuffer[256] = {0};
  const unsigned int data_len = (scan_size + 7) / 8;
  if(data_len > sizeof(txBuffer)-8){
    return -1;
  }
  unsigned int len = 8;
  if(buffered){
    txBuffer[0] = ir_scan ? JTAG_TCP2_CMD_IRSCAN_BUFFERED : JTAG_TCP2_CMD_DRSCAN_BUFFERED;
  }else{
    txBuffer[0] = ir_scan ? JTAG_TCP2_CMD_IRSCAN : JTAG_TCP2_CMD_DRSCAN;
  }

  txBuffer[1] = scan_size;
  memcpy(txBuffer+2,buffer,data_len);

  len += data_len;
  if(send(client_socket,(char*)txBuffer,len, 0) <= 0){
		return -1;
  }

	return 0;
}

static int jtag_tcp2_scan_rsp(int client_socket, uint8_t *buffer, int scan_size){
  uint32_t rxBuffer[256] = {0};
  const unsigned int data_len = (scan_size + 7) / 8;
  if(data_len > sizeof(rxBuffer)){
    return -1;
  }
  unsigned int remaining = data_len;
  while(remaining){
    unsigned int cnt = read(client_socket,buffer,remaining);
    buffer+=cnt;
    remaining -= cnt;
    if(cnt == 0){
      return -1;
    }
	}
  return 0;
}

static int jtag_tcp2_scan(int client_socket, bool ir_scan, uint8_t *buffer, int scan_size){
  if(jtag_tcp2_scan_cmd(client_socket, ir_scan, buffer, scan_size,0)) return -1;
  return jtag_tcp2_scan_rsp(client_socket, buffer, scan_size);
}

static int jtag_tcp2_stableclocks(int client_socket, int num_cycles){
  uint32_t txBuffer[2];
  txBuffer[0] = JTAG_TCP2_CMD_IDLE;
  txBuffer[1] = num_cycles;

	if(send(client_socket,(char*)txBuffer,sizeof(txBuffer), 0) <= 0){
		return -1;
  }

	return 0;
}

static int jtag_tcp2_runtest(int client_socket, int num_cycles){
  uint32_t txBuffer[2];
  txBuffer[0] = JTAG_TCP2_CMD_RUNTEST;
  txBuffer[1] = num_cycles;

  if(send(client_socket,(char*)txBuffer,sizeof(txBuffer), 0) <= 0){
    return -1;
  }

  return 0;
}

static int jtag_tcp2_set_chain (int client_socket, unsigned int ir_chain_length,unsigned int ir_tap_pos,unsigned int ir_tap_length,unsigned int chain_taps,unsigned int chain_tap_pos){
  uint32_t cmd = JTAG_TCP2_CMD_CHAIN;
  jtag_chain_cfg_t cfg = {
    ir_chain_length,
    ir_tap_pos,
    ir_tap_length,
    chain_taps,
    chain_tap_pos
  };
  char buf[sizeof(cmd)+sizeof(jtag_chain_cfg_t)];
  memcpy(buf,&cmd,sizeof(cmd));
  memcpy(buf+sizeof(cmd),&cfg,sizeof(cfg));
  if(send(client_socket,buf,sizeof(buf), 0) <= 0){
    return -1;
  }
  return 0;
}

static int jtag_tcp2_flush(int client_socket){
  uint32_t txBuffer[1];
  txBuffer[0] = JTAG_TCP2_CMD_FLUSH;

  if(send(client_socket,(char*)txBuffer,sizeof(txBuffer), 0) <= 0){
    return -1;
  }

  return 0;
}

static int jtag_tcp2_lock(int client_socket){
  uint32_t txBuffer[1];
  txBuffer[0] = JTAG_TCP2_CMD_LOCK;

  if(send(client_socket,(char*)txBuffer,sizeof(txBuffer), 0) <= 0){
    return -1;
  }

  return 0;
}

static int jtag_tcp2_release(int client_socket){
  uint32_t txBuffer[1];
  txBuffer[0] = JTAG_TCP2_CMD_RELEASE;

  if(send(client_socket,(char*)txBuffer,sizeof(txBuffer), 0) <= 0){
    return -1;
  }

  return 0;
}

static void jtag_tcp2_remove_unused_warning(void){
    (void)jtag_tcp2_init;
    (void)jtag_tcp2_reset;
    (void)jtag_tcp2_scan;
    (void)jtag_tcp2_stableclocks;
    (void)jtag_tcp2_runtest;
    (void)jtag_tcp2_set_chain;
    (void)jtag_tcp2_flush;
    (void)jtag_tcp2_lock;
    (void)jtag_tcp2_release;
}

#endif //__JTAG_TCP2_H__
