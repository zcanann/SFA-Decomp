#ifndef MAIN_DLL_DLL_00F2_ICEBLAST_H_
#define MAIN_DLL_DLL_00F2_ICEBLAST_H_

#include "main/game_object.h"

/*
 * iceblast (DLL 0xF2) - a path-following ice projectile in the
 * pushable/transporter object family. Public interface: the placement
 * descriptor and the object-class callbacks, so consumers include this
 * instead of hand-writing externs.
 */
typedef struct IceblastPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 useAltHitVolume; /* 0x19: nonzero selects hit-volume slot 3, else 1 */
    s16 initialTimer;   /* 0x1a: seeds the countdown timer at init */
    u8 pad1C[4];
} IceblastPlacement;

int iceblast_getExtraSize(void);
int iceblast_getObjectTypeId(void);
void iceblast_free(void);
void iceblast_render(int* obj, int p1, int p2, int p3, int p4);
void iceblast_hitDetect(void);
void iceblast_update(GameObject* obj);
void iceblast_init(GameObject* obj, IceblastPlacement* def);
void iceblast_release(void);
void iceblast_initialise(void);

#endif
