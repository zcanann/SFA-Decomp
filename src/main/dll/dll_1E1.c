#include "ghidra_import.h"
#include "main/dll/dll_1E1.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800217c8();
extern uint FUN_80022264();
extern undefined4 FUN_8002b070();
extern byte FUN_8002b11c();
extern undefined4 FUN_8002b128();
extern undefined4 FUN_8002b754();
extern int FUN_8002bac4();
extern int FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035ea4();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036548();
extern int FUN_80036868();
extern undefined4 FUN_8009a468();
extern undefined4 FUN_801d21ec();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern double FUN_8029686c();
extern byte FUN_80296ba8();
extern int FUN_80296bb8();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5fa0;
extern f64 DOUBLE_803e5fe0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e5f90;
extern f32 FLOAT_803e5f94;
extern f32 FLOAT_803e5fb0;
extern f32 FLOAT_803e5fb4;
extern f32 FLOAT_803e5fb8;
extern f32 FLOAT_803e5fbc;
extern f32 FLOAT_803e5fc0;
extern f32 FLOAT_803e5fc4;
extern f32 FLOAT_803e5fc8;
extern f32 FLOAT_803e5fcc;
extern f32 FLOAT_803e5fd0;
extern f32 FLOAT_803e5fd4;
extern f32 FLOAT_803e5fd8;

/*
 * --INFO--
 *
 * Function: FUN_801d2414
 * EN v1.0 Address: 0x801D1E24
 * EN v1.0 Size: 2644b
 * EN v1.1 Address: 0x801D2414
 * EN v1.1 Size: 2452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2414(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  float fVar2;
  ushort *puVar3;
  int iVar4;
  byte bVar7;
  int iVar5;
  uint uVar6;
  uint *puVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  undefined4 in_r10;
  char cVar12;
  int iVar13;
  float *pfVar14;
  double dVar15;
  uint uStack_58;
  int iStack_54;
  undefined4 uStack_50;
  undefined auStack_4c [12];
  float local_40;
  float local_3c;
  float local_38 [2];
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  puVar3 = (ushort *)FUN_80286840();
  pfVar14 = *(float **)(puVar3 + 0x5c);
  iVar4 = FUN_8002bac4();
  iVar13 = *(int *)(puVar3 + 0x26);
  FUN_80035ea4((int)puVar3);
  *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
  *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 4;
  bVar7 = FUN_8002b11c((int)puVar3);
  if (bVar7 == 0) {
    if ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0) {
      switch(*(undefined *)((int)pfVar14 + 0x36)) {
      default:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(puVar3 + 6);
        param_3 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(puVar3 + 8));
        fVar2 = *(float *)(iVar4 + 0x14) - *(float *)(puVar3 + 10);
        dVar15 = FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1 + (float)(param_3 * param_3)));
        local_30 = (double)(longlong)(int)dVar15;
        param_2 = (double)FLOAT_803e5fd0;
        uStack_24 = (uint)*(byte *)(iVar13 + 0x1e);
        local_28 = 0x43300000;
        uVar6 = (uint)(param_2 *
                      (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e5fe0));
        local_20 = (double)(longlong)(int)uVar6;
        if ((((int)dVar15 & 0xffffU) < (uVar6 & 0xffff)) &&
           (dVar15 = FUN_8029686c(iVar4), (double)FLOAT_803e5fd4 <= dVar15)) {
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfe;
          *(undefined *)((int)pfVar14 + 0x36) = 3;
          *pfVar14 = FLOAT_803e5f94;
          FUN_8000bb38((uint)puVar3,0x48e);
        }
        break;
      case 1:
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfb;
        if (pfVar14[1] < *(float *)(puVar3 + 4)) {
          pfVar14[4] = pfVar14[4] / FLOAT_803e5fc0;
        }
        if (pfVar14[4] < FLOAT_803e5f90) {
          pfVar14[4] = FLOAT_803e5f94;
        }
        *pfVar14 = *pfVar14 + FLOAT_803dc074;
        param_2 = (double)pfVar14[4];
        *(float *)(puVar3 + 4) =
             (float)(param_2 * (double)FLOAT_803dc074 + (double)*(float *)(puVar3 + 4));
        if (pfVar14[2] < *pfVar14) {
          *(undefined *)((int)pfVar14 + 0x36) = 0;
        }
        break;
      case 2:
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfb;
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          iVar4 = (uint)*(byte *)(puVar3 + 0x1b) + (uint)DAT_803dc070 * -4;
          if (iVar4 < 0) {
            iVar4 = 0;
          }
          *(char *)(puVar3 + 0x1b) = (char)iVar4;
          *pfVar14 = *pfVar14 + FLOAT_803dc074;
          param_2 = (double)*pfVar14;
          local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar14 + 0xd) ^ 0x80000000);
          if ((double)(float)(local_30 - DOUBLE_803e5fa0) < param_2) {
            FUN_801d21ec(puVar3,pfVar14,1);
            *(undefined *)((int)pfVar14 + 0x36) = 1;
          }
        }
        break;
      case 3:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        FUN_8000da78((uint)puVar3,0x9c);
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          *(undefined *)((int)pfVar14 + 0x36) = 4;
        }
        break;
      case 4:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        param_2 = (double)FLOAT_803e5fb8;
        pfVar14[0xb] = (float)(param_2 * (double)FLOAT_803dc074 + (double)pfVar14[0xb]);
        FUN_8000da78((uint)puVar3,0x9a);
        if (((((*(byte *)((int)pfVar14 + 0x37) & 1) == 0) &&
             (dVar15 = (double)FUN_800217c8((float *)(puVar3 + 0xc),(float *)(iVar4 + 0x18)),
             dVar15 <= (double)pfVar14[0xb])) && (iVar5 = FUN_80296bb8(iVar4), iVar5 == 0)) &&
           ((bVar7 = FUN_80296ba8(iVar4), bVar7 == 0 && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0))
           )) {
          FUN_80036548(iVar4,(int)puVar3,'\x16',1,0);
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 1;
        }
        if (FLOAT_803e5fb4 < pfVar14[0xb]) {
          pfVar14[0xb] = FLOAT_803e5fb4;
        }
        *pfVar14 = *pfVar14 + FLOAT_803dc074;
        if (FLOAT_803e5fbc < *pfVar14) {
          *pfVar14 = FLOAT_803e5f94;
          *(undefined *)((int)pfVar14 + 0x36) = 5;
        }
        local_40 = pfVar14[8];
        local_3c = pfVar14[9];
        local_38[0] = pfVar14[10];
        for (cVar12 = '\x01'; cVar12 != '\0'; cVar12 = cVar12 + -1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x3eb,auStack_4c,0x200001,0xffffffff,0);
        }
        break;
      case 5:
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        *pfVar14 = *pfVar14 + FLOAT_803dc074;
        param_2 = (double)*pfVar14;
        local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar13 + 0x18));
        if (((double)(float)(local_30 - DOUBLE_803e5fe0) < param_2) &&
           ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0)) {
          *(undefined *)((int)pfVar14 + 0x36) = 0;
          pfVar14[0xb] = FLOAT_803e5f94;
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfe;
        }
        break;
      case 6:
        FUN_8000da78((uint)puVar3,0x9a);
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfb;
        param_2 = (double)FLOAT_803e5fb0;
        pfVar14[0xb] = (float)(param_2 * (double)FLOAT_803dc074 + (double)pfVar14[0xb]);
        if (FLOAT_803e5fb4 < pfVar14[0xb]) {
          pfVar14[0xb] = FLOAT_803e5fb4;
        }
        if (((((*(byte *)((int)pfVar14 + 0x37) & 1) == 0) &&
             (dVar15 = (double)FUN_800217c8((float *)(puVar3 + 0xc),(float *)(iVar4 + 0x18)),
             dVar15 <= (double)pfVar14[0xb])) && (iVar5 = FUN_80296bb8(iVar4), iVar5 == 0)) &&
           ((bVar7 = FUN_80296ba8(iVar4), bVar7 == 0 && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0))
           )) {
          FUN_80036548(iVar4,(int)puVar3,'\x16',1,0);
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 1;
        }
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          *pfVar14 = FLOAT_803e5f94;
          *(undefined *)((int)pfVar14 + 0x36) = 2;
        }
        local_40 = pfVar14[8];
        local_3c = pfVar14[9];
        local_38[0] = pfVar14[10];
        for (cVar12 = '\x01'; cVar12 != '\0'; cVar12 = cVar12 + -1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x3eb,auStack_4c,0x200001,0xffffffff,0);
        }
        break;
      case 9:
        if (*pfVar14 <= FLOAT_803e5f94) {
          uVar6 = FUN_80022264(0xf0,300);
          local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          *pfVar14 = (float)(local_30 - DOUBLE_803e5fa0);
        }
        if ((*(byte *)((int)pfVar14 + 0x37) & 2) != 0) {
          *pfVar14 = FLOAT_803e5f94;
        }
        FUN_8000da78((uint)puVar3,0x9b);
        fVar1 = *pfVar14 - FLOAT_803dc074;
        *pfVar14 = fVar1;
        param_2 = (double)FLOAT_803e5f94;
        if (param_2 < (double)fVar1) {
          fVar1 = pfVar14[0xc] - FLOAT_803dc074;
          pfVar14[0xc] = fVar1;
          if ((double)fVar1 <= param_2) {
            local_40 = FLOAT_803e5fc4;
            local_3c = FLOAT_803e5fc8;
            (**(code **)(*DAT_803dd708 + 8))(puVar3,0x51d,auStack_4c,2,0xffffffff,0);
            pfVar14[0xc] = FLOAT_803e5fcc;
          }
          *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        }
        else {
          (**(code **)(*DAT_803dd6f8 + 0x14))(puVar3);
          *(undefined *)((int)pfVar14 + 0x36) = 0;
          FUN_8002b754((int)puVar3);
        }
        break;
      case 10:
        FUN_80035ff8((int)puVar3);
        *pfVar14 = *pfVar14 + FLOAT_803dc074;
        param_2 = (double)*pfVar14;
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar14 + 0xd) ^ 0x80000000);
        if ((double)(float)(local_30 - DOUBLE_803e5fa0) < param_2) {
          FUN_801d21ec(puVar3,pfVar14,1);
          *(undefined *)((int)pfVar14 + 0x36) = 1;
          FUN_8002b754((int)puVar3);
        }
      }
      puVar8 = &uStack_58;
      pfVar9 = &local_40;
      pfVar10 = &local_3c;
      pfVar11 = local_38;
      iVar4 = FUN_80036868((int)puVar3,&uStack_50,&iStack_54,puVar8,pfVar9,pfVar10,pfVar11);
      local_40 = local_40 + FLOAT_803dda58;
      local_38[0] = local_38[0] + FLOAT_803dda5c;
      if ((iVar4 != 0) && ((*(byte *)((int)pfVar14 + 0x37) & 4) != 0)) {
        if (iVar4 == 0x10) {
          FUN_8002b128(puVar3,300);
        }
        else {
          if (*(char *)((int)pfVar14 + 0x36) != '\t') {
            FUN_8000bb38((uint)puVar3,0x9d);
          }
          *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfe;
          if ((int)*(short *)(iVar13 + 0x1c) != 0xffffffff) {
            FUN_800201ac((int)*(short *)(iVar13 + 0x1c),1);
          }
          *(undefined *)((int)pfVar14 + 0x36) = 9;
          *pfVar14 = FLOAT_803e5f94;
          uVar6 = FUN_80022264(0,0x28);
          local_20 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          *(float *)(puVar3 + 0x4c) = (float)(local_20 - DOUBLE_803e5fa0) / FLOAT_803e5fd8;
        }
        puVar8 = (uint *)0x0;
        FUN_8009a468(puVar3,auStack_4c,1,(int *)0x0);
      }
      iVar4 = (int)*(short *)((uint)*(byte *)((int)pfVar14 + 0x36) * 2 + -0x7fcd8748);
      if ((short)puVar3[0x50] != iVar4) {
        FUN_8003042c((double)FLOAT_803e5f94,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar3,iVar4,0,puVar8,pfVar9,pfVar10,pfVar11,in_r10);
      }
      iVar4 = FUN_8002fb40((double)*(float *)((uint)*(byte *)((int)pfVar14 + 0x36) * 4 + -0x7fcd8730
                                             ),(double)FLOAT_803dc074);
      if (iVar4 == 0) {
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) & 0xfd;
      }
      else {
        *(byte *)((int)pfVar14 + 0x37) = *(byte *)((int)pfVar14 + 0x37) | 2;
      }
    }
  }
  else {
    iVar4 = FUN_80036868((int)puVar3,&uStack_50,&iStack_54,&uStack_58,&local_40,&local_3c,local_38);
    if ((iVar4 != 0) && (iVar4 != 0x10)) {
      local_40 = local_40 + FLOAT_803dda58;
      local_38[0] = local_38[0] + FLOAT_803dda5c;
      FUN_8009a468(puVar3,auStack_4c,1,(int *)0x0);
      FUN_8000bb38((uint)puVar3,0x47b);
      FUN_8002b070((int)puVar3);
    }
  }
  FUN_8028688c();
  return;
}
