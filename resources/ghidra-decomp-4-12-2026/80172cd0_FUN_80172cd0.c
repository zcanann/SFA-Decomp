// Function: FUN_80172cd0
// Entry: 80172cd0
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x80172f50) */
/* WARNING: Removing unreachable block (ram,0x80172ce0) */

void FUN_80172cd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  float *pfVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  uVar2 = (uint)((ulonglong)uVar10 >> 0x20);
  pfVar6 = (float *)uVar10;
  iVar7 = *(int *)(uVar2 + 0x4c);
  iVar3 = FUN_8002bac4();
  if ((iVar3 == 0) || ((*(byte *)((int)pfVar6 + 0x37) & 1) != 0)) goto LAB_80172f50;
  iVar4 = FUN_80297a08(iVar3);
  if (iVar4 == 0) {
    iVar4 = iVar3;
  }
  dVar8 = (double)FUN_80021754((float *)(uVar2 + 0x18),(float *)(iVar4 + 0x18));
  dVar9 = (double)(*(float *)(iVar4 + 0x1c) - *(float *)(uVar2 + 0x1c));
  if (dVar9 < (double)FLOAT_803e40f4) {
    dVar9 = -dVar9;
  }
  if (((dVar9 < (double)FLOAT_803e4128) && (dVar8 < (double)pfVar6[1])) &&
     (uVar5 = FUN_8029698c(iVar3), uVar5 != 0)) {
    *(undefined2 *)(pfVar6 + 0x12) = 0xffff;
    sVar1 = *(short *)(uVar2 + 0x46);
    if (sVar1 == 0x319) {
      FUN_80172308(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
    }
    else if (sVar1 < 0x319) {
      if (sVar1 == 0x49) {
LAB_80172e44:
        uVar5 = FUN_80020078(0x90f);
        if (uVar5 == 0) {
          FUN_800379bc(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                       uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
          FUN_800201ac(0x90f,1);
        }
        else {
          FUN_80172308(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
        }
        *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
      }
      else {
        if (sVar1 < 0x49) {
          if (sVar1 == 0xb) {
            uVar5 = FUN_80020078(0x90e);
            if (uVar5 == 0) {
              FUN_800379bc(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,
                           0x7000a,uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
              FUN_800201ac(0x90e,1);
            }
            else {
              FUN_80172308(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
            }
            *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
            goto LAB_80172f4c;
          }
        }
        else if (sVar1 == 0x2da) goto LAB_80172e44;
LAB_80172eec:
        iVar4 = FUN_8003811c(uVar2);
        if (iVar4 != 0) {
          uVar10 = FUN_800201ac(0xa7b,1);
          *(undefined2 *)(pfVar6 + 0x12) = *(undefined2 *)(iVar7 + 0x1e);
          FUN_800379bc(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                       uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
          *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
          if (*(int *)(uVar2 + 100) != 0) {
            *(undefined4 *)(*(int *)(uVar2 + 100) + 0x30) = 0x1000;
          }
        }
      }
    }
    else {
      if (sVar1 != 0x6a6) {
        if ((0x6a5 < sVar1) || (sVar1 != 0x3cd)) goto LAB_80172eec;
        goto LAB_80172e44;
      }
      uVar5 = FUN_80020078(0x9a8);
      if (uVar5 == 0) {
        FUN_800379bc(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                     uVar2,(uint)(pfVar6 + 0x12),in_r7,in_r8,in_r9,in_r10);
        FUN_800201ac(0x9a8,1);
      }
      else {
        FUN_80172308(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      }
      *(byte *)((int)pfVar6 + 0x37) = *(byte *)((int)pfVar6 + 0x37) | 1;
    }
  }
LAB_80172f4c:
  *pfVar6 = (float)dVar8;
LAB_80172f50:
  FUN_8028688c();
  return;
}

