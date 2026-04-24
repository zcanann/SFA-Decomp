// Function: FUN_80169d94
// Entry: 80169d94
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x8016a150) */
/* WARNING: Removing unreachable block (ram,0x8016a148) */
/* WARNING: Removing unreachable block (ram,0x8016a140) */
/* WARNING: Removing unreachable block (ram,0x80169db4) */
/* WARNING: Removing unreachable block (ram,0x80169dac) */
/* WARNING: Removing unreachable block (ram,0x80169da4) */

void FUN_80169d94(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 local_48;
  undefined8 local_40;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  local_48 = (double)CONCAT44(0x43300000,*(uint *)(param_9 + 0x7a) ^ 0x80000000);
  *(int *)(param_9 + 0x7a) = (int)((float)(local_48 - DOUBLE_803e3d80) - FLOAT_803dc074);
  if (*(int *)(param_9 + 0x7a) < 0) {
    uVar5 = FUN_8000b7dc((int)param_9,0x7f);
    FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  else if (*(char *)(param_9 + 0x1b) != '\0') {
    if (*(int *)(param_9 + 0x7a) < 0x11b) {
      *(float *)(param_9 + 0x14) = -(FLOAT_803e3d88 * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b));
      param_4 = (double)(FLOAT_803e3d8c * FLOAT_803dc074);
      if ((float)((double)(float)(local_40 - DOUBLE_803e3d98) - param_4) <= FLOAT_803e3d90) {
        FUN_8000b7dc((int)param_9,0x7f);
        *(undefined *)(param_9 + 0x1b) = 0;
      }
      else {
        local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b));
        *(char *)(param_9 + 0x1b) =
             (char)(int)((double)(float)(local_40 - DOUBLE_803e3d98) - param_4);
      }
      FUN_8000b8a8((double)FLOAT_803e3d94,(int)param_9,0x40,
                   (byte)((int)(uint)*(byte *)(param_9 + 0x1b) >> 1));
    }
    dVar10 = (double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074);
    dVar8 = (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074);
    dVar6 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
    dVar7 = dVar6;
    dVar9 = dVar8;
    FUN_8002ba34(dVar10,dVar8,dVar6,(int)param_9);
    if (param_9[0x23] == 0x869) {
      FUN_80035eec((int)param_9,0x1f,1,0);
      *param_9 = *param_9 + 0x100;
      param_9[1] = param_9[1] + 0x800;
    }
    else {
      FUN_80035eec((int)param_9,10,1,0);
      iVar2 = FUN_80021884();
      *param_9 = (short)iVar2 + -0x8000;
      dVar8 = dVar9;
      FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar7 * dVar7)));
      iVar2 = FUN_80021884();
      param_9[1] = 0x4000 - (short)iVar2;
    }
    uVar5 = FUN_80036018((int)param_9);
    if (*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) {
      if (*(int *)(param_9 + 0x7a) < 0x17c) {
        FUN_80169b80(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
        return;
      }
      iVar2 = FUN_8002bac4();
      if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar2) ||
         (iVar2 = FUN_8002ba84(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar2)) {
        FUN_80169b80(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
        return;
      }
    }
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) == '\0') {
      if (param_9[0x23] == 0x869) {
        FUN_80098da4(param_9,1,0,0,(undefined4 *)0x0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x714,0,2,0xffffffff,param_9 + 0x1b);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,0);
      }
      iVar2 = *piVar4;
      if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0'))
      {
        uVar3 = FUN_80022264(0xffffffe7,0x19);
        iVar2 = *piVar4;
        sVar1 = (ushort)*(byte *)(iVar2 + 0x2f9) + (short)*(char *)(iVar2 + 0x2fa) + (short)uVar3;
        if (sVar1 < 0) {
          sVar1 = 0;
          *(undefined *)(iVar2 + 0x2fa) = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
          *(undefined *)(iVar2 + 0x2fa) = 0;
        }
        *(char *)(*piVar4 + 0x2f9) = (char)sVar1;
      }
    }
    else {
      FUN_80169b80(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
    }
  }
  return;
}

