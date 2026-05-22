#include "ghidra_import.h"
#include "main/dll/dll_13F.h"

extern uint GameBit_Get(int eventId);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjLink_DetachChild();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801713ac();
extern undefined8 FUN_801723dc();
extern undefined8 FUN_801726ac();
extern undefined4 FUN_80172974();
extern undefined4 FUN_80172b40();
extern uint countLeadingZeros();
extern void fn_80172680(void);

extern undefined4 DAT_803218a8;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e40d8;
extern undefined4 DAT_803e40dc;
extern f64 DOUBLE_803e40e0;
extern f32 lbl_803DC074;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern f32 lbl_803E40F0;
extern f32 lbl_803E40F4;
extern f32 lbl_803E412C;
extern f32 lbl_803E4130;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern void *gPathControlInterface;
extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 lbl_803E345C;
extern f32 lbl_803E3494;
extern f32 lbl_803E3498;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;

/*
 * --INFO--
 *
 * Function: collectible_init
 * EN v1.0 Address: 0x80172F14
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801730D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void collectible_init(int obj,int setup)
{
  int state;
  int setupObj;
  int data;
  u32 pathWord;
  u8 pathByte;

  state = *(int *)(obj + 0xb8);
  pathWord = lbl_803E3440;
  pathByte = lbl_803E3444;
  ObjGroup_AddObject(obj,4);
  ObjMsg_AllocQueue(obj,2);
  *(s16 *)(obj + 0) = (s16)((u8)*(u8 *)(setup + 0x1b) << 8);
  *(s16 *)(obj + 2) = (s16)((u8)*(u8 *)(setup + 0x22) << 8);
  *(s16 *)(obj + 4) = (s16)((u8)*(u8 *)(setup + 0x23) << 8);
  setupObj = *(int *)(obj + 0x50);
  *(f32 *)(obj + 8) = *(f32 *)(setupObj + 4);
  *(void (**)(void))(obj + 0xbc) = fn_80172680;
  *(s8 *)(obj + 0xad) = *(s8 *)(setup + 0x26);
  if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
    *(u8 *)(obj + 0xad) = 0;
  }
  *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x2000;
  *(u8 *)(state + 0xc) = *(u8 *)(setup + 0x19);
  *(u8 *)(state + 0xd) = *(u8 *)(setup + 0x1a);
  *(u8 *)(state + 0xf) = 0;
  *(s32 *)(state + 0x18) = -2;
  *(u8 *)(state + 0x1d) = 0;
  *(s16 *)(state + 0x14) = *(s16 *)(setup + 0x24);
  *(u32 *)(state + 0x20) = *(u32 *)(setup + 0x14);
  *(f32 *)(state + 0x24) = *(f32 *)(obj + 0xc);
  *(f32 *)(state + 0x28) = *(f32 *)(obj + 0x10);
  *(f32 *)(state + 0x2c) = *(f32 *)(obj + 0x14);
  *(u8 *)(state + 0x36) = *(u8 *)(setup + 0x27);
  *(u8 *)(state + 0x3e) = 0;
  if (*(s16 *)(state + 0x14) != -1) {
    *(u8 *)(state + 0x1e) = (u8)(__cntlzw(GameBit_Get(*(s16 *)(state + 0x14))) >> 5);
  }
  *(s16 *)(state + 0x10) = *(s16 *)(setup + 0x1c);
  if (*(s16 *)(state + 0x10) != -1) {
    *(u32 *)(obj + 0xf4) = GameBit_Get(*(s16 *)(state + 0x10));
  } else {
    *(u32 *)(obj + 0xf4) = 0;
  }
  if (*(u32 *)(obj + 0xf4) == 0) {
    data = *(int *)(*(int *)(obj + 0x50) + 0x18);
    if (data != 0) {
      *(f32 *)(state + 4) = (f32)*(s8 *)(data + 8);
    } else {
      *(f32 *)(state + 4) = lbl_803E3494;
    }
    data = *(int *)(*(int *)(obj + 0x50) + 0x40);
    if (data != 0) {
      *(f32 *)(state + 4) = (f32)((u32)*(u8 *)(data + 0xc) << 2);
    }
    if (((*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 0x10000) != 0) &&
        (*(u8 *)(state + 0x36) != 0)) {
      *(u8 *)(state + 0x38) = *(u8 *)(setup + 0x28);
      *(u8 *)(state + 0x39) = *(u8 *)(setup + 0x29);
      *(u8 *)(state + 0x3a) = *(u8 *)(setup + 0x2a);
    }
    switch (*(s16 *)(obj + 0x46)) {
      case 0xb:
        *(f32 *)(state + 0x40) = lbl_803E345C;
        *(f32 *)(state + 0x44) = lbl_803E3498;
        break;
      case 0x3cd:
        *(f32 *)(state + 0x40) = lbl_803E349C;
        *(f32 *)(state + 0x44) = lbl_803E3498;
        break;
      default:
        *(f32 *)(state + 0x40) = lbl_803E34A0;
        break;
    }
    (*(void (**)(int,int,int,int))(*(int *)gPathControlInterface + 4))(state + 0x50,0,0x40006,1);
    (*(void (**)(int,int,u8 *,u32 *,u8 *))(*(int *)gPathControlInterface + 0xc))
        (state + 0x50,1,lbl_80320C58,&pathWord,&pathByte);
    (*(void (**)(int,int))(*(int *)gPathControlInterface + 0x20))(obj,state + 0x50);
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80173364
 * EN v1.0 Address: 0x80173364
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801733C0
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173364(short *param_1,int param_2)
{
}

extern void *gExpgfxInterface;

#pragma scheduling off
#pragma peephole off
void magicdust_free(int param_1)
{
  if (*(uint *)(param_1 + 0xc4) != 0) {
    ObjLink_DetachChild(*(int *)(param_1 + 0xc4), param_1);
  }
  (*(void (***)(int))gExpgfxInterface)[6](param_1);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801733c0
 * EN v1.0 Address: 0x801733C0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017372C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801733c0(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: collectible_release
 * EN v1.0 Address: 0x8017321C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80173378
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_release(void)
{
}

/*
 * --INFO--
 *
 * Function: collectible_initialise
 * EN v1.0 Address: 0x80173220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017337C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int magicdust_getExtraSize(void) { return 0x288; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E34B0;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void magicdust_render(void) { objRenderFn_8003b8f4(lbl_803E34B0); }
#pragma peephole reset
#pragma scheduling reset
