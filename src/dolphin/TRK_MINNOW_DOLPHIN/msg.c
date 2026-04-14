/* TODO: restore stripped imported address metadata if needed. */

/**
 * msg.c
 * Description:
 */

#include "PowerPC_EABI_Support/MetroTRK/trk.h"

DSError TRKMessageSend(TRKBuffer* msg) {
    DSError writeErr = TRKWriteUARTN(&msg->data, msg->length);
    MWTRACE(1, "MessageSend : cc_write returned %ld\n", writeErr);
    return DS_NoError;
}
