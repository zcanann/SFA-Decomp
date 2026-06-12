#ifndef MAIN_OBJSEQ_CONTROL_H_
#define MAIN_OBJSEQ_CONTROL_H_

/*
 * Sequence callbacks write these bits into ObjAnimUpdateState/ObjSeqState
 * byte +0x90. ObjSeq_update consumes them as paired set/clear requests for
 * three per-slot latch arrays, plus a saved-frame restart request.
 */
#define OBJSEQ_CONTROL_SET_LATCH_B 0x01
#define OBJSEQ_CONTROL_CLEAR_LATCH_B 0x02
#define OBJSEQ_CONTROL_SET_LATCH_A 0x04
#define OBJSEQ_CONTROL_CLEAR_LATCH_A 0x08
#define OBJSEQ_CONTROL_SET_STATE_LATCH 0x10
#define OBJSEQ_CONTROL_CLEAR_STATE_LATCH 0x20
#define OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME 0x40

#endif /* MAIN_OBJSEQ_CONTROL_H_ */
