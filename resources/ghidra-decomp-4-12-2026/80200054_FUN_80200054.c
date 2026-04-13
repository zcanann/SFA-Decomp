// Function: FUN_80200054
// Entry: 80200054
// Size: 864 bytes

/* WARNING: Removing unreachable block (ram,0x80200390) */
/* WARNING: Removing unreachable block (ram,0x80200388) */
/* WARNING: Removing unreachable block (ram,0x8020006c) */
/* WARNING: Removing unreachable block (ram,0x80200064) */
/* WARNING: Removing unreachable block (ram,0x802000b4) */

void FUN_80200054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  float fVar5;
  float *pfVar6;
  double dVar7;
  double dVar8;
  float afStack_68 [3];
  float afStack_5c [3];
  undefined2 local_50;
  short local_4e;
  undefined2 local_4c;
  undefined4 local_38;
  float fStack_34;
  
  pfVar6 = *(float **)(param_9 + 0x5c);
  iVar3 = FUN_8002bac4();
  fVar5 = FLOAT_803e6f14;
  bVar1 = *(byte *)(pfVar6 + 2);
  if (bVar1 == 3) {
    dVar7 = (double)FUN_80021754((float *)(param_9 + 0xc),(float *)(iVar3 + 0x18));
    if ((double)FLOAT_803dcdd0 <= dVar7) {
      dVar8 = (double)FLOAT_803dcdd4;
      FUN_80222268((double)(float)(dVar8 / (double)FLOAT_803e6f2c),param_2,param_3,param_4,param_5,
                   param_6,param_7,param_8,iVar3,(float *)(param_9 + 6),afStack_5c);
      FUN_80247eb8(afStack_5c,(float *)(param_9 + 6),afStack_68);
      FUN_80247ef8(afStack_68,afStack_68);
      if (dVar7 < dVar8) {
        dVar8 = dVar7;
      }
      FUN_80247edc(dVar8,afStack_68,(float *)(param_9 + 0x12));
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                   (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                   (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      local_4c = 0xff;
      local_4e = 0;
      local_50 = 0xff;
      FUN_80098bb4((double)FLOAT_803dcddc,param_9,1,0xc22,0x14,param_9 + 0x12);
    }
    else {
      FUN_8029725c(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,DAT_803dcdd8)
      ;
      FUN_8000bb38((uint)param_9,0x49);
      *(undefined *)(pfVar6 + 2) = 4;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (FLOAT_803e6f14 < *pfVar6 - *(float *)(param_9 + 8)) {
        *(float *)(param_9 + 0x14) = FLOAT_803e6f18 * -*(float *)(param_9 + 0x14);
        fVar2 = *(float *)(param_9 + 0x14);
        if (fVar2 < fVar5) {
          fVar2 = -fVar2;
        }
        if (fVar2 < FLOAT_803e6f1c) {
          *(undefined *)(pfVar6 + 2) = 2;
          fVar5 = FLOAT_803e6f14;
          *(float *)(param_9 + 0x12) = FLOAT_803e6f14;
          *(float *)(param_9 + 0x16) = fVar5;
          goto LAB_80200364;
        }
      }
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + FLOAT_803e6f20;
      FUN_8002ba34((double)*(float *)(param_9 + 0x12),(double)*(float *)(param_9 + 0x14),
                   (double)*(float *)(param_9 + 0x16),(int)param_9);
      local_4c = 0xff;
      fVar5 = pfVar6[1];
      iVar3 = (int)fVar5 / 0x500 + ((int)fVar5 >> 0x1f);
      local_4e = 0xff - (SUB42(fVar5,0) + ((short)iVar3 - (short)(iVar3 >> 0x1f)) * -0x500);
      local_50 = 0xff;
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x357,&local_50,0,0xffffffff,0);
    }
    else if (bVar1 == 0) {
      uVar4 = FUN_80020078((int)*(short *)(*(int *)(param_9 + 0x26) + 0x20));
      if (uVar4 == 1) {
        *(undefined *)(pfVar6 + 2) = 2;
      }
    }
    else {
      fStack_34 = -pfVar6[1];
      local_38 = 0x43300000;
      dVar7 = (double)FUN_802945e0();
      *(float *)(param_9 + 0x14) = (float)((double)FLOAT_803dcdc8 * dVar7);
      FUN_8002ba34((double)*(float *)(param_9 + 0x12),(double)*(float *)(param_9 + 0x14),
                   (double)*(float *)(param_9 + 0x16),(int)param_9);
      dVar7 = (double)FUN_800217c8((float *)(param_9 + 0xc),(float *)(iVar3 + 0x18));
      if (dVar7 < (double)FLOAT_803dcdcc) {
        *(undefined *)(pfVar6 + 2) = 3;
      }
      FUN_80098bb4((double)FLOAT_803dcddc,param_9,1,0xc22,0x14,param_9 + 0x12);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(pfVar6 + 2) = 0;
  }
LAB_80200364:
  *param_9 = *param_9 + DAT_803dcde0;
  pfVar6[1] = (float)((int)pfVar6[1] + (uint)DAT_803dc070 * 0x500);
  return;
}

