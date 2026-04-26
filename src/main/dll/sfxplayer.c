#include "ghidra_import.h"
#include "main/dll/sfxplayer.h"

extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern void fn_8001467C(void);
extern int fn_8001FFB4(int eventId);
extern void TrickyCurve_activateEffectHandleRing(void);
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803e70e8;
extern undefined4 DAT_803e70ec;
extern f32 FLOAT_803e7110;

/*
 * --INFO--
 *
 * Function: sfxplayer_update
 * EN v1.0 Address: 0x80207CE4
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x80207F80
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int handleIndex;
  uint uVar1;
  undefined2 *puVar2;
  char cVar5;
  undefined4 uVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 uVar7;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar7 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar7 >> 0x20);
  local_28 = DAT_803e70e8;
  local_24 = DAT_803e70ec;
  uVar6 = extraout_f1;
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    uVar1 = (uint)uVar7 & 0xff;
    handleIndex = uVar1 * 2;
    if (gSfxplayerEffectHandles[handleIndex] == 0) {
      puVar2 = FUN_80017aa4(0x2c,0x6e8);
      *(undefined *)(puVar2 + 3) = 0xff;
      *(undefined *)((int)puVar2 + 7) = 0xff;
      *(undefined *)(puVar2 + 2) = 2;
      *(undefined *)((int)puVar2 + 5) = 1;
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x14);
      puVar2[0x12] = 0xffff;
      *(undefined *)(puVar2 + 0xd) = 0;
      *(undefined *)(puVar2 + 0xc) = 0;
      *(undefined *)((int)puVar2 + 0x19) = 0;
      cVar5 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar4 + 0xac));
      if (cVar5 == '\x02') {
        *(char *)((int)puVar2 + 0x1b) = (char)*(undefined2 *)((int)&local_28 + uVar1 * 2);
      }
      else {
        *(char *)((int)puVar2 + 0x1b) = (char)local_24;
      }
      *(undefined *)(puVar2 + 0xe) = 0;
      *(undefined *)((int)puVar2 + 0x1d) = 0;
      *(undefined *)(puVar2 + 0x13) = 100;
      *(undefined *)((int)puVar2 + 0x27) = 0;
      *(undefined *)(puVar2 + 0x14) = 0;
      *(float *)(puVar2 + 0x10) = FLOAT_803e7110;
      *(undefined *)((int)puVar2 + 0x29) = 0xd2;
      *(undefined *)(puVar2 + 0x15) = 0;
      uVar3 = FUN_80017ae4(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           puVar2,5,*(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30)
                           ,in_r8,in_r9,in_r10);
      gSfxplayerEffectHandles[handleIndex] = uVar3;
      uVar6 = extraout_f1_01;
    }
    if (gSfxplayerEffectHandles[handleIndex + 1] == 0) {
      puVar2 = FUN_80017aa4(4,0x71c);
      *(undefined *)(puVar2 + 3) = 0xff;
      *(undefined *)((int)puVar2 + 7) = 0xff;
      *(undefined *)(puVar2 + 2) = 2;
      *(undefined *)((int)puVar2 + 5) = 1;
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x14);
      iVar4 = FUN_80017ae4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                           *(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30),in_r8,
                           in_r9,in_r10);
      gSfxplayerEffectHandles[handleIndex + 1] = iVar4;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: sfxplayer_init
 * EN v1.0 Address: 0x80207FBC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8020816C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_init(int obj,int config)
{
  int state;

  state = *(int *)(obj + 0xb8);
  *(s16 *)obj = (s16)((s8)*(u8 *)(config + 0x18) << 8);
  *(void (**)(void))(obj + 0xbc) = TrickyCurve_activateEffectHandleRing;
  *(u8 *)(state + 6) = *(u8 *)(config + 0x19);
  *(s16 *)state = *(s16 *)(config + 0x1e);
  *(s16 *)(state + 2) = *(s16 *)(config + 0x20);
  *(s16 *)(state + 4) = 1;
  gSfxplayerEffectHandles[0] = 0;
  gSfxplayerEffectHandles[1] = 0;
  gSfxplayerEffectHandles[2] = 0;
  gSfxplayerEffectHandles[3] = 0;
  gSfxplayerEffectHandles[4] = 0;
  gSfxplayerEffectHandles[5] = 0;
  gSfxplayerEffectHandles[6] = 0;
  gSfxplayerEffectHandles[7] = 0;
  fn_8001467C();
  if (fn_8001FFB4(*(s16 *)state) != 0) {
    *(u8 *)(state + 8) = *(u8 *)(state + 8) | 0x20;
  }
  *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x6000;
}

/*
 * --INFO--
 *
 * Function: sfxplayer_release
 * EN v1.0 Address: 0x80208090
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208240
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_release(void)
{
}

/*
 * --INFO--
 *
 * Function: sfxplayer_initialise
 * EN v1.0 Address: 0x80208094
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208244
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_initialise(void)
{
}
