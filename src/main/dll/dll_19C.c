#include "ghidra_import.h"
#include "main/dll/dll_19C.h"

extern undefined8 FUN_80008cbc();
extern undefined4 FUN_80009a94();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern byte FUN_8001469c();
extern undefined4 FUN_800146a8();
extern undefined4 FUN_800146c8();
extern undefined4 FUN_800146e8();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001f448();
extern void* FUN_8001f58c();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021754();
extern uint FUN_80021884();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern int FUN_8002e1ac();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80043604();
extern int FUN_8004832c();
extern undefined8 FUN_80088f20();
extern undefined4 FUN_8009a010();
extern undefined4 FUN_8014ca38();
extern undefined4 FUN_801d84c4();
extern undefined4 FUN_801d8650();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80296c78();
extern uint FUN_80296cb4();
extern undefined4 FUN_80297184();

extern ushort DAT_80326bc8;
extern undefined4 DAT_80326bdc;
extern ushort DAT_80326bf0;
extern int DAT_80326c04;
extern undefined4 DAT_803dcbc8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5b18;
extern f64 DOUBLE_803e5b28;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5ae8;
extern f32 FLOAT_803e5aec;
extern f32 FLOAT_803e5af0;
extern f32 FLOAT_803e5af4;
extern f32 FLOAT_803e5b00;
extern f32 FLOAT_803e5b04;
extern f32 FLOAT_803e5b08;
extern f32 FLOAT_803e5b0c;
extern f32 FLOAT_803e5b10;
extern f32 FLOAT_803e5b20;
extern f32 FLOAT_803e5b24;
extern f32 FLOAT_803e5b30;

/*
 * --INFO--
 *
 * Function: FUN_801c2ec8
 * EN v1.0 Address: 0x801C2E68
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C2EC8
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2ec8(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002bac4();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0x14) =
         *(short *)(iVar3 + 0x14) + (short)(int)(FLOAT_803e5ae8 * FLOAT_803dc074);
    *(short *)(iVar3 + 0x16) =
         *(short *)(iVar3 + 0x16) + (short)(int)(FLOAT_803e5aec * FLOAT_803dc074);
    *(short *)(iVar3 + 0x18) =
         *(short *)(iVar3 + 0x18) + (short)(int)(FLOAT_803e5af0 * FLOAT_803dc074);
    dVar5 = (double)FUN_802945e0();
    *(float *)(param_1 + 8) = FLOAT_803e5af4 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[2] = (ushort)(int)(FLOAT_803e5b00 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[1] = (ushort)(int)(FLOAT_803e5b00 * (float)(dVar6 + dVar5));
    FUN_8002fb40((double)FLOAT_803e5b04,(double)FLOAT_803dc074);
    if (iVar1 != 0) {
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5b18) * FLOAT_803dc074) /
                             FLOAT_803e5b08);
      dVar5 = (double)FUN_80021754((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)FLOAT_803e5b0c < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(FLOAT_803e5b10 * (float)(dVar5 / (double)FLOAT_803e5b0c));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c321c
 * EN v1.0 Address: 0x801C3134
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801C321C
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c321c(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_8028683c();
  piVar5 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80296c78(iVar3,1,1);
        FUN_800201ac(0xbfd,1);
        FUN_800201ac(0x956,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,2);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)(piVar5 + 7) = *(byte *)(piVar5 + 7) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_8001dc30((double)FLOAT_803e5b20,*piVar5,'\0');
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_8001dc30((double)FLOAT_803e5b20,*piVar5,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c3388
 * EN v1.0 Address: 0x801C3288
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801C3388
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3388(int param_1)
{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  puVar3 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar3;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar3 = 0;
  }
  FUN_800146a8();
  iVar2 = FUN_8004832c(0x1f);
  FUN_80043604(iVar2,1,0);
  FUN_8000a538((int *)0xd8,0);
  FUN_8000a538((int *)0xd9,0);
  FUN_8000a538((int *)0x8,0);
  FUN_800201ac(0xefa,0);
  FUN_800201ac(0xcbb,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c341c
 * EN v1.0 Address: 0x801C331C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C341C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c341c(void)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5b20,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5b20,*piVar2,'\x01');
    }
    FUN_8003b9ec(iVar1);
    FUN_8009a010((double)FLOAT_803e5b20,(double)FLOAT_803e5b20,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c34d8
 * EN v1.0 Address: 0x801C33B4
 * EN v1.0 Size: 1768b
 * EN v1.1 Address: 0x801C34D8
 * EN v1.1 Size: 1508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c34d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  float fVar1;
  bool bVar2;
  double dVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar9;
  int *piVar8;
  ushort *puVar10;
  int iVar11;
  ushort *puVar12;
  undefined8 uVar13;
  
  puVar12 = &DAT_80326bc8;
  iVar11 = *(int *)(param_9 + 0x5c);
  iVar6 = FUN_8002bac4();
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar13 = FUN_80088f20(7,'\x01');
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar6,0x78,0,in_r7,in_r8,in_r9,in_r10);
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar6,0x79,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6,0x222,
                 0,in_r7,in_r8,in_r9,in_r10);
  }
  FUN_801c2ec8(param_9);
  if (DAT_803dcbc8 != '\0') {
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
    FUN_80297184(iVar6,0x14);
    FUN_800201ac(0x1d7,1);
    DAT_803dcbc8 = '\0';
  }
  FUN_801d8650(iVar11 + 0xc,1,-1,-1,0xcbb,(int *)0x8);
  FUN_801d84c4(iVar11 + 0xc,4,-1,-1,0xcbb,(int *)0xc4);
  fVar4 = FLOAT_803e5b24;
  dVar3 = DOUBLE_803e5b18;
  uVar5 = (int)*(short *)(iVar11 + 0x12) ^ 0x80000000;
  if ((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e5b18) <= FLOAT_803e5b24) {
    switch(*(undefined *)(iVar11 + 0x1a)) {
    case 0:
      fVar1 = *(float *)(iVar11 + 8) - FLOAT_803dc074;
      *(float *)(iVar11 + 8) = fVar1;
      if (fVar1 <= fVar4) {
        FUN_8000bb38((uint)param_9,0x343);
        uVar5 = FUN_80022264(500,1000);
        *(float *)(iVar11 + 8) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e5b18);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        FUN_800201ac(0x589,0);
        *(undefined *)(iVar11 + 0x1a) = 5;
        FUN_8000a538((int *)0xd8,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_800201ac(0x129,0);
      }
      break;
    case 1:
      if (*(char *)(iVar11 + 0x1c) < '\0') {
        *(undefined *)(iVar11 + 0x1a) = 2;
        FUN_800201ac(0xb76,1);
        FUN_800146e8(0x19,0xd2);
        FUN_800146c8();
      }
      break;
    case 2:
      if ((*(byte *)(iVar11 + 0x1b) < 10) &&
         (*(float *)(iVar11 + 4) = *(float *)(iVar11 + 4) - FLOAT_803dc074,
         *(float *)(iVar11 + 4) <= fVar4)) {
        FUN_800201ac((uint)(ushort)(&DAT_80326bc8)[*(byte *)(iVar11 + 0x1b)],1);
        *(float *)(iVar11 + 4) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (&DAT_80326bdc + (uint)*(byte *)(iVar11 + 0x1b) * 2)) -
                    DOUBLE_803e5b28);
        *(char *)(iVar11 + 0x1b) = *(char *)(iVar11 + 0x1b) + '\x01';
      }
      bVar2 = false;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        uVar5 = FUN_80020078((uint)(ushort)(&DAT_80326bf0)[sVar9]);
        if (uVar5 == 0) {
          bVar2 = true;
          sVar9 = 10;
        }
      }
      if (bVar2) {
        bVar7 = FUN_8001469c();
        if (bVar7 != 0) {
          *(undefined *)(iVar11 + 0x1a) = 7;
          *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf;
          *(undefined2 *)(iVar11 + 0x12) = 0x78;
          piVar8 = &DAT_80326c04;
          for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
            if ((*piVar8 != -1) && (iVar6 = FUN_8002e1ac(*piVar8), iVar6 != 0)) {
              FUN_8014ca38(iVar6);
            }
            piVar8 = piVar8 + 1;
          }
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 7;
        *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf | 0x40;
        FUN_800146a8();
      }
      break;
    case 3:
      uVar5 = FUN_80296cb4(iVar6,1);
      if ((uVar5 == 0) && (uVar5 = FUN_80020078(0xbfd), uVar5 == 0)) {
        if ((*(byte *)(iVar11 + 0x1c) >> 6 & 1) == 0) {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_800201ac(0xb70,1);
        }
        else {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_80009a94(3);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 4;
      }
      FUN_800201ac(0x129,1);
      FUN_800201ac(0xb76,0);
      break;
    case 4:
      *(undefined *)(iVar11 + 0x1a) = 0;
      *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0x7f;
      *(undefined *)(iVar11 + 0x1b) = 0;
      *(float *)(iVar11 + 4) = fVar4;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0xb70,0);
      FUN_800201ac(0xb71,0);
      FUN_800201ac(0xb76,0);
      FUN_800201ac(0x589,1);
      puVar10 = &DAT_80326bf0;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        FUN_800201ac((uint)*puVar10,0);
        FUN_800201ac((uint)*puVar12,0);
        puVar10 = puVar10 + 1;
        puVar12 = puVar12 + 1;
      }
      param_9[3] = param_9[3] & 0xbfff;
      break;
    case 5:
      *(undefined2 *)(iVar11 + 0x12) = 0x1f;
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
      *(undefined *)(iVar11 + 0x1a) = 1;
      param_9[3] = param_9[3] | 0x4000;
      break;
    case 6:
      *(undefined *)(iVar11 + 0x1a) = 3;
      break;
    case 7:
      *(undefined *)(iVar11 + 0x1a) = 6;
      *(undefined2 *)(iVar11 + 0x12) = 0x23;
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
    }
  }
  else {
    *(short *)(iVar11 + 0x12) =
         (short)(int)((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e5b18) - FLOAT_803dc074
                     );
    if ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x12) ^ 0x80000000) - dVar3) <=
        fVar4) {
      *(undefined2 *)(iVar11 + 0x12) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c3abc
 * EN v1.0 Address: 0x801C3A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C3ABC
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3abc(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c3bdc
 * EN v1.0 Address: 0x801C3AA0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801C3BDC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3bdc(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(uint *)(iVar1 + 0x140) != 0) {
    FUN_8001f448(*(uint *)(iVar1 + 0x140));
    *(undefined4 *)(iVar1 + 0x140) = 0;
    *(undefined *)(iVar1 + 0x144) = 0;
  }
  (**(code **)(*DAT_803dd6d4 + 0x24))(iVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c3c38
 * EN v1.0 Address: 0x801C3B00
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801C3C38
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c3c38(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    if (*(char *)(iVar1 + 0x144) == '\0') {
      FUN_8009a010((double)FLOAT_803e5b30,(double)FLOAT_803e5b30,param_1,7,(int *)0x0);
    }
    else {
      FUN_8009a010((double)FLOAT_803e5b30,(double)FLOAT_803e5b30,param_1,7,*(int **)(iVar1 + 0x140))
      ;
    }
  }
  return;
}
