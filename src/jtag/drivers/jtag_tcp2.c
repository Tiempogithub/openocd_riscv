//Sebastien Riou
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/interface.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#endif
#include <string.h>
#include <fcntl.h>
#include "hello.h"

#include "jtag_tcp2.h" //from jtaghub repo

/* my private tap controller state, which tracks state for calling code */
static tap_state_t jtag_tcp_state;

int clientSocket;

static int jtag_tcp2_khz(int khz, int *jtag_speed){
  LOG_DEBUG("%s", __func__);
	if (khz == 0)
		*jtag_speed = 0;
	else
		*jtag_speed = 64000/khz;
	return ERROR_OK;
}

static int jtag_tcp2_speed_div(int speed, int *khz){
  LOG_DEBUG("%s", __func__);
	if (speed == 0)
		*khz = 0;
	else
		*khz = 64000/speed;

	return ERROR_OK;
}

static int jtag_tcp2_speed(int speed){
  LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int openocd_jtag_tcp2_init(void){
	jtag_tcp_state = TAP_RESET;
  jtag_tcp2_remove_unused_warning();
  int port = 7895;
  const char *host = "127.0.0.1";
	if(jtag_tcp2_init(&clientSocket,port,host)){
		LOG_ERROR("jtag_tcp2: Can't connect to the TCP server at %s:%d",host,port);
		return ERROR_FAIL;
	}
  LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int jtag_tcp2_quit(void){
  LOG_DEBUG("%s", __func__);
	return close(clientSocket);
}


static int openocd_jtag_tcp2_reset(void){
  LOG_DEBUG("%s", __func__);
	if(jtag_tcp2_reset(clientSocket))
		return ERROR_FAIL;

	tap_set_state(TAP_RESET);
  return ERROR_OK;
}

#define OPENOCD_JTAG_TCP2_BUFFERED 1
static int openocd_jtag_tcp2_scan(bool ir_scan, enum scan_type type, uint8_t *buffer, int scan_size){
  LOG_DEBUG("%s scan_type=%d", __func__,type);
  uint8_t txBuffer[256] = {0};
  const unsigned int data_len = (scan_size + 7) / 8;
  if(data_len > sizeof(txBuffer)){
    LOG_DEBUG("scan_size too large: %d",scan_size);
    return ERROR_FAIL;
  }
  if(type != SCAN_IN){//weird isn't it XD
    memcpy(txBuffer,buffer,data_len);
  }
  if(jtag_tcp2_scan_cmd(clientSocket, ir_scan, txBuffer, scan_size,OPENOCD_JTAG_TCP2_BUFFERED))
		return ERROR_FAIL;

	return ERROR_OK;
}

static int openocd_jtag_tcp2_scan_rsp(bool ir_scan, enum scan_type type, uint8_t *buffer, int scan_size){
  LOG_DEBUG("%s scan_type=%d", __func__,type);

  uint8_t rxBuffer[256] = {0};
  const unsigned int data_len = (scan_size + 7) / 8;
  if(data_len > sizeof(rxBuffer)){
    LOG_DEBUG("scan_size too large: %d",scan_size);
    return ERROR_FAIL;
  }
  if(type == SCAN_OUT){
    LOG_DEBUG("type == SCAN_OUT");
    buffer = (uint8_t*) rxBuffer;
  }else{
    LOG_DEBUG("type != SCAN_OUT");
  }
  if(jtag_tcp2_scan_rsp(clientSocket, buffer, scan_size))
    return ERROR_FAIL;
	return ERROR_OK;
}

static int openocd_jtag_tcp2_stableclocks(int num_cycles){
  LOG_DEBUG("%s", __func__);
	if(jtag_tcp2_stableclocks(clientSocket, num_cycles))
		return ERROR_FAIL;

	return ERROR_OK;
}

static int openocd_jtag_tcp2_runtest(int num_cycles){
  LOG_DEBUG("%s", __func__);
  if(jtag_tcp2_runtest(clientSocket, num_cycles))
		return ERROR_FAIL;

  return ERROR_OK;
}

static int openocd_jtag_tcp2_flush(void){
  #if OPENOCD_JTAG_TCP2_BUFFERED
    LOG_DEBUG("%s", __func__);
    if(jtag_tcp2_flush(clientSocket)) return ERROR_FAIL;
  #endif
  return ERROR_OK;
}
static int openocd_jtag_tcp2_lock(void){
  LOG_DEBUG("%s", __func__);
  if(jtag_tcp2_lock(clientSocket))
		return ERROR_FAIL;

  return ERROR_OK;
}
static int openocd_jtag_tcp2_release(void){
  LOG_DEBUG("%s", __func__);
  if(jtag_tcp2_release(clientSocket))
		return ERROR_FAIL;

  return ERROR_OK;
}

int jtag_tcp2_execute_queue(void){
  LOG_DEBUG("%s", __func__);
  struct jtag_command *cmd;
	int retval = ERROR_OK;
	uint8_t *buffer;
	int scan_size;
	enum scan_type type;
  int cmdcnt=0;

	for (cmd = jtag_command_queue; retval == ERROR_OK && cmd != NULL;
	     cmd = cmd->next) {
    if(cmdcnt==0) openocd_jtag_tcp2_lock();
    cmdcnt++;
		switch (cmd->type) {
		case JTAG_RESET:
      LOG_DEBUG("JTAG_RESET");
			retval = openocd_jtag_tcp2_reset();
			break;
		case JTAG_TLR_RESET:
      LOG_DEBUG("JTAG_RESET");
      retval = openocd_jtag_tcp2_reset();
      break;
		case JTAG_SLEEP:
      LOG_DEBUG("JTAG_SLEEP");
			break;
		case JTAG_SCAN:
      LOG_DEBUG("JTAG_SCAN");
			scan_size = jtag_build_buffer(cmd->cmd.scan, &buffer);
			type = jtag_scan_type(cmd->cmd.scan);
			if (openocd_jtag_tcp2_scan(cmd->cmd.scan->ir_scan, type, buffer, scan_size) != ERROR_OK)
				retval = ERROR_JTAG_QUEUE_FAILED;
			if (buffer)
				free(buffer);
			break;
		case JTAG_STABLECLOCKS:
      LOG_DEBUG("JTAG_STABLECLOCKS");
			retval = openocd_jtag_tcp2_stableclocks(cmd->cmd.stableclocks->num_cycles);
			break;
		case JTAG_RUNTEST:
      LOG_DEBUG("JTAG_RUNTEST");
		  retval = openocd_jtag_tcp2_runtest(cmd->cmd.runtest->num_cycles);
			break;
		default:
			LOG_ERROR("unknow cmd ???");
			retval = ERROR_FAIL;
			break;
		}
	}
  if(cmdcnt) openocd_jtag_tcp2_flush();
  LOG_DEBUG("response loop");
	for (cmd = jtag_command_queue; retval == ERROR_OK && cmd != NULL;
	     cmd = cmd->next) {
		switch (cmd->type) {
			break;
		case JTAG_SCAN:
			scan_size = jtag_build_buffer(cmd->cmd.scan, &buffer);
			type = jtag_scan_type(cmd->cmd.scan);
			if (openocd_jtag_tcp2_scan_rsp(cmd->cmd.scan->ir_scan, type, buffer, scan_size) != ERROR_OK)
				retval = ERROR_JTAG_QUEUE_FAILED;
			if (jtag_read_buffer(buffer, cmd->cmd.scan) != ERROR_OK)
				retval = ERROR_JTAG_QUEUE_FAILED;
			if (buffer)
				free(buffer);
			break;
		default:
			break;
		}
	}
	if(retval != 0)
		LOG_ERROR("jtag_tcp2 queue error\n");
  if(cmdcnt) openocd_jtag_tcp2_release();
	return retval;
}


int jtag_tcp2_streset(int srst, int trst){
  LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}


static const struct command_registration jtag_tcp2_command_handlers[] = {
	{
		.name = "jtag_tcp2",
		.usage = "",
		.mode = COMMAND_ANY,
		.help = "jtag_tcp2 interface driver commands",
		.chain = hello_command_handlers,
	},
	COMMAND_REGISTRATION_DONE,
};


/* The jtag_tcp driver is used to easily check the code path
 * where the target is unresponsive.
 */
static struct jtag_interface jtag_tcp2_interface = {
  .supported = DEBUG_CAP_TMS_SEQ,
  .execute_queue = &jtag_tcp2_execute_queue
};
struct adapter_driver jtag_tcp2_adapter_driver = {
  .name = "jtag_tcp2",

  .commands = jtag_tcp2_command_handlers,
  .transports = jtag_only,

  .reset = jtag_tcp2_streset,

  .speed = &jtag_tcp2_speed,
  .khz = &jtag_tcp2_khz,
  .speed_div = &jtag_tcp2_speed_div,

  .init = &openocd_jtag_tcp2_init,
  .quit = &jtag_tcp2_quit,

  .jtag_ops = &jtag_tcp2_interface,
  .swd_ops = NULL,
};
