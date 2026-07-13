#ifndef MAIN_DLL_DLL_00D1_TUMBLEWEEDBUSH_H_
#define MAIN_DLL_DLL_00D1_TUMBLEWEEDBUSH_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

/* Bush variant anim.seqIds and the sibling tumbleweed seqId each one spawns.
 * The sibling ids match dll_00D2_tumbleweed.h's TUMBLEWEED_TYPE_1/3/4
 * (0x39d/0x4ba/0x4c1). */
#define TUMBLEWEEDBUSH_SEQ_A 0x28d /* -> sibling 0x39d (sun-gated) */
#define TUMBLEWEEDBUSH_SEQ_B 0x3fd /* -> sibling 0x3fb */
#define TUMBLEWEEDBUSH_SEQ_C 0x4b9 /* -> sibling 0x4ba */
#define TUMBLEWEEDBUSH_SEQ_D 0x4be /* -> sibling 0x4c1 */

#define TUMBLEWEEDBUSH_OBJGROUP 0x31 /* group scanned to find sibling bushes */

#define TUMBLEWEEDBUSH_SIBLING_A 0x39d
#define TUMBLEWEEDBUSH_SIBLING_B 0x3fb
#define TUMBLEWEEDBUSH_SIBLING_C 0x4ba
#define TUMBLEWEEDBUSH_SIBLING_D 0x4c1

extern ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor;


/* extern-cleanup: defining-file public prototypes */
s8 fn_801631C8(int* obj);

#endif /* MAIN_DLL_DLL_00D1_TUMBLEWEEDBUSH_H_ */
