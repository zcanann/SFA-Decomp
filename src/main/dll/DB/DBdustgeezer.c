#include "ghidra_import.h"
#include "main/dll/DB/DBdustgeezer.h"

extern undefined8 FUN_80006728();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern undefined4 FUN_80017a98();
extern int FUN_80017af8();

/*
 * --INFO--
 *
 * Function: FUN_801e1588
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 1624b
 * EN v1.1 Address: 0x801E167C
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e1588(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar4;
  
  uVar1 = FUN_80017a98();
  uVar2 = GameBit_Get(0xa3c);
  if (uVar2 != 0) {
    iVar3 = FUN_80017af8(0x467e8);
    uVar4 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,uVar1
                         ,(uint)*(byte *)(param_9 + (uint)*(byte *)(param_9 + 0xa4) + 0xa9),0,in_r7,
                         in_r8,in_r9,in_r10);
    iVar3 = FUN_80017af8(0x467e7);
    uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,uVar1,
                         (uint)*(byte *)(param_9 + (*(byte *)(param_9 + 0xa4) ^ 1) + 0xa7),0,in_r7,
                         in_r8,in_r9,in_r10);
    FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x96,0,
                 in_r7,in_r8,in_r9,in_r10);
    param_1 = GameBit_Set(0xa3c,0);
    *(undefined2 *)(param_9 + 0xa2) = 0xa3e;
  }
  uVar2 = GameBit_Get(0xa3d);
  if (uVar2 != 0) {
    iVar3 = FUN_80017af8(0x467e7);
    uVar4 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,uVar1
                         ,(uint)*(byte *)(param_9 + (uint)*(byte *)(param_9 + 0xa4) + 0xa9),0,in_r7,
                         in_r8,in_r9,in_r10);
    iVar3 = FUN_80017af8(0x467e8);
    uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,uVar1,
                         (uint)*(byte *)(param_9 + (*(byte *)(param_9 + 0xa4) ^ 1) + 0xa7),0,in_r7,
                         in_r8,in_r9,in_r10);
    FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x96,0,
                 in_r7,in_r8,in_r9,in_r10);
    param_1 = GameBit_Set(0xa3d,0);
    *(undefined2 *)(param_9 + 0xa2) = 0xa3f;
  }
  uVar2 = GameBit_Get(0xa3e);
  if (uVar2 != 0) {
    if (*(short *)(param_9 + 0xa2) != 0xa3e) {
      *(byte *)(param_9 + 0xa4) = *(byte *)(param_9 + 0xa4) ^ 1;
    }
    uVar4 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1
                         ,(uint)*(byte *)(param_9 + (*(byte *)(param_9 + 0xa4) ^ 1) + 0xa5),0,in_r7,
                         in_r8,in_r9,in_r10);
    uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                         (uint)*(byte *)(param_9 + (uint)*(byte *)(param_9 + 0xa4) + 0xa9),0,in_r7,
                         in_r8,in_r9,in_r10);
    FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x8a,0,
                 in_r7,in_r8,in_r9,in_r10);
    param_1 = GameBit_Set(0xa3e,0);
  }
  uVar2 = GameBit_Get(0xa3f);
  if (uVar2 != 0) {
    if (*(short *)(param_9 + 0xa2) != 0xa3f) {
      *(byte *)(param_9 + 0xa4) = *(byte *)(param_9 + 0xa4) ^ 1;
    }
    uVar4 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1
                         ,(uint)*(byte *)(param_9 + (*(byte *)(param_9 + 0xa4) ^ 1) + 0xa5),0,in_r7,
                         in_r8,in_r9,in_r10);
    uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                         (uint)*(byte *)(param_9 + (uint)*(byte *)(param_9 + 0xa4) + 0xa9),0,in_r7,
                         in_r8,in_r9,in_r10);
    FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x8a,0,
                 in_r7,in_r8,in_r9,in_r10);
    GameBit_Set(0xa3f,0);
  }
  return;
}
