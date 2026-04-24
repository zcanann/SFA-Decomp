#include "ghidra_import.h"
#include "main/dll/CF/CFTreasSharpy.h"

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern uint FUN_80017760();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80135814();
extern undefined4 FUN_8018dc28();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dca50;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e4ac0;
extern f32 FLOAT_803e4a70;
extern f32 FLOAT_803e4a84;
extern f32 FLOAT_803e4a8c;
extern f32 FLOAT_803e4a94;
extern f32 FLOAT_803e4ac8;
extern f32 FLOAT_803e4acc;
extern f32 FLOAT_803e4ad0;
extern f32 FLOAT_803e4ad4;
extern f32 FLOAT_803e4ad8;
extern f32 FLOAT_803e4ae0;

/*
 * --INFO--
 *
 * Function: FUN_8018e0a4
 * EN v1.0 Address: 0x8018E0A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E620
 * EN v1.1 Size: 1568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018e0a4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,short *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018e0a8
 * EN v1.0 Address: 0x8018E0A8
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x8018EC40
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018e0a8(void)
{
  byte bVar1;
  undefined2 *puVar2;
  int *piVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  puVar2 = (undefined2 *)FUN_80286840();
  iVar7 = *(int *)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  uVar6 = 0;
  if (*(short *)(iVar7 + 10) == 0x11) {
    FUN_80135814();
  }
  bVar1 = *(byte *)(iVar4 + 0x28);
  if (bVar1 == 2) {
    sVar5 = *(short *)(iVar7 + 8);
    if (sVar5 == 0) {
      uVar6 = 0x200001;
    }
    if (sVar5 == 1) {
      uVar6 = 1;
    }
    if (sVar5 == 2) {
      uVar6 = 1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      sVar5 = *(short *)(iVar7 + 8);
      if (sVar5 == 0) {
        uVar6 = 2;
      }
      if (sVar5 == 1) {
        uVar6 = 2;
      }
      if (sVar5 == 2) {
        uVar6 = 2;
      }
    }
    else {
      sVar5 = *(short *)(iVar7 + 8);
      if (sVar5 == 0) {
        uVar6 = 4;
      }
      if (sVar5 == 1) {
        uVar6 = 4;
      }
      if (sVar5 == 2) {
        uVar6 = 4;
      }
    }
  }
  else if (bVar1 < 4) {
    uVar6 = 0;
  }
  else {
    uVar6 = 2;
  }
  if ((uVar6 & 1) == 0) {
    sVar5 = *(short *)(iVar7 + 8);
    if (sVar5 == 0) {
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar2,(int)*(short *)(iVar7 + 10),0,uVar6,0xffffffff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar2,(int)*(short *)(iVar7 + 10),0,uVar6,0xffffffff,0);
        }
      }
    }
    else if (sVar5 == 1) {
      piVar3 = (int *)FUN_80006b14((int)*(short *)(iVar7 + 10) + 0x58U & 0xffff);
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,0);
        }
      }
      FUN_80006b0c((undefined *)piVar3);
    }
    else if (sVar5 == 2) {
      piVar3 = (int *)FUN_80006b14((int)*(short *)(iVar7 + 10) + 0xabU & 0xffff);
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,*(ushort *)(iVar7 + 10) & 0xff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,*(ushort *)(iVar7 + 10) & 0xff,0);
        }
      }
      FUN_80006b0c((undefined *)piVar3);
    }
  }
  else {
    local_2c = *(undefined4 *)(puVar2 + 6);
    local_28 = *(undefined4 *)(puVar2 + 8);
    local_24 = *(undefined4 *)(puVar2 + 10);
    local_38 = *puVar2;
    local_34 = puVar2[2];
    local_36 = puVar2[1];
    local_30 = FLOAT_803e4ae0;
    if (*(short *)(iVar7 + 0xe) < 1) {
      (**(code **)(*DAT_803dd708 + 8))
                (puVar2,(int)*(short *)(iVar7 + 0xc),&local_38,uVar6,0xffffffff,0);
    }
    else {
      for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar2,(int)*(short *)(iVar7 + 10),&local_38,uVar6,0xffffffff,0);
      }
    }
  }
  FUN_8028688c();
  return;
}
