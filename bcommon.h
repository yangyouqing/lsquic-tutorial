#ifndef __BCOMMON_H__
#define __BCOMMON_H__

/* bcommon.h
   define the msg send/recv between bclient and bserver.
*/
typedef enum msg_type {
    MSG_TYPE_CMD_SEND_DATA_START,
    MSG_TYPE_CMD_SEND_DATA_END,
    MSG_TYPE_DATA
} msg_type_e;

typedef struct msgdata {
    msg_type_e type;
    uint32_t len;
    uint8_t val[0];
} msg_data_t;




#endif