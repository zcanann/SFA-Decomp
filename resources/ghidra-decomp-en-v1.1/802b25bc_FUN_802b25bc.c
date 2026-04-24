// Function: FUN_802b25bc
// Entry: 802b25bc
// Size: 1600 bytes

/* WARNING: Removing unreachable block (ram,0x802b2bd8) */
/* WARNING: Removing unreachable block (ram,0x802b2bd0) */
/* WARNING: Removing unreachable block (ram,0x802b2bc8) */
/* WARNING: Removing unreachable block (ram,0x802b25dc) */
/* WARNING: Removing unreachable block (ram,0x802b25d4) */
/* WARNING: Removing unreachable block (ram,0x802b25cc) */

void FUN_802b25bc(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,int param_11)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  short sVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double in_f31;
  float local_78;
  float local_74;
  undefined4 *local_70;
  float local_6c [4];
  float local_5c;
  float local_58;
  float local_54;
  undefined8 local_50;
  undefined8 local_48;
  
  fVar1 = FLOAT_803e8b78;
  iVar9 = 0;
  *(float *)(param_10 + 0x82c) = FLOAT_803e8b78;
  *(float *)(param_10 + 0x834) = fVar1;
  *(float *)(param_10 + 0x830) = FLOAT_803e8ddc;
  *(undefined *)(param_10 + 0x86c) = 0;
  bVar3 = (*(byte *)(param_10 + 0x3f0) >> 5 & 1) == 0;
  if ((bVar3) || ((!bVar3 && (FLOAT_803e8d68 != *(float *)(param_11 + 0x1c0))))) {
    *(undefined4 *)(param_10 + 0x83c) = *(undefined4 *)(param_11 + 0x1c0);
  }
  if (FLOAT_803e8d68 == *(float *)(param_10 + 0x83c)) {
    *(float *)(param_10 + 0x838) = FLOAT_803e8b3c;
  }
  else {
    *(float *)(param_10 + 0x838) = *(float *)(param_10 + 0x83c) - *(float *)(param_9 + 0x1c);
  }
  *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xfe;
  dVar11 = (double)FLOAT_803e8b3c;
  local_74 = FLOAT_803e8b3c;
  local_78 = FLOAT_803e8b3c;
  if ((*(byte *)(param_11 + 0x264) & 0x10) != 0) {
    *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xfe | 1;
    *(undefined *)(param_10 + 0x86c) = *(undefined *)(param_11 + 0xbc);
    fVar1 = FLOAT_803e8b78;
    switch(*(undefined *)(param_10 + 0x86c)) {
    case 3:
      *(float *)(param_10 + 0x82c) = FLOAT_803e8b78;
      *(float *)(param_10 + 0x834) = fVar1;
      *(float *)(param_10 + 0x830) = FLOAT_803e8c04;
      break;
    default:
      *(undefined2 *)(param_10 + 0x808) = 0;
      if (*(float *)(param_10 + 0x7c8) < FLOAT_803e8b3c) {
        fVar1 = FLOAT_803e8b94 * *(float *)(param_11 + 0x280) + *(float *)(param_10 + 0x7c8);
        fVar2 = FLOAT_803e8b3c;
        if (fVar1 < FLOAT_803e8b3c) {
          fVar2 = fVar1;
        }
        *(float *)(param_10 + 0x7c8) = fVar2;
        in_f31 = -(double)*(float *)(param_10 + 0x7c8);
      }
      break;
    case 6:
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(param_10 + 0x808) ^ 0x80000000);
      iVar6 = (int)((double)(float)(local_50 - DOUBLE_803e8b58) - param_1);
      local_48 = (double)(longlong)iVar6;
      sVar4 = (short)iVar6;
      *(short *)(param_10 + 0x808) = sVar4;
      if (sVar4 < 1) {
        *(undefined2 *)(param_10 + 0x808) = 0x3c;
        FUN_80036548(param_9,0,'\x14',2,0);
      }
      break;
    case 8:
      FUN_80036548(param_9,0,'\x01',0,0);
      break;
    case 0xd:
      *(float *)(param_10 + 0x82c) = FLOAT_803e8de0;
      *(float *)(param_10 + 0x834) = FLOAT_803e8de4;
      *(float *)(param_10 + 0x830) = FLOAT_803e8db0;
      break;
    case 0x1a:
      local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(param_10 + 0x808) ^ 0x80000000);
      iVar6 = (int)((double)(float)(local_48 - DOUBLE_803e8b58) - param_1);
      local_50 = (double)(longlong)iVar6;
      sVar4 = (short)iVar6;
      *(short *)(param_10 + 0x808) = sVar4;
      if (sVar4 < 1) {
        *(undefined2 *)(param_10 + 0x808) = 0x3c;
        FUN_80038524(param_9,0xb,&local_5c,&local_58,&local_54,0);
        FUN_800366b0((double)local_5c,(double)local_58,(double)local_54,param_9,0,'\x14',2,0xff);
      }
      break;
    case 0x1c:
      uVar5 = FUN_80020078(0x21);
      if (uVar5 == 0) {
        local_48 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x8a0));
        iVar6 = (int)((double)(float)(local_48 - DOUBLE_803e8bd0) + param_1);
        local_50 = (double)(longlong)iVar6;
        *(short *)(param_10 + 0x8a0) = (short)iVar6;
        if (0x78 < *(ushort *)(param_10 + 0x8a0)) {
          *(ushort *)(param_10 + 0x8a0) = *(ushort *)(param_10 + 0x8a0) - 0x78;
          FUN_80038524(param_9,0xb,&local_5c,&local_58,&local_54,0);
          FUN_800366b0((double)local_5c,(double)local_58,(double)local_54,param_9,0,'\x16',2,0xff);
        }
      }
      break;
    case 0x1d:
      local_6c[0] = FLOAT_803e8de8;
      iVar9 = FUN_80036f50(0x16,param_9,local_6c);
      if (iVar9 != 0) {
        (**(code **)(**(int **)(iVar9 + 0x68) + 0x20))
                  ((double)FLOAT_803e8b78,iVar9,param_9,&local_74,&local_78);
      }
      break;
    case 0x1f:
      FUN_800201ac(0x643,1);
      break;
    case 0x20:
      if (*(float *)(param_11 + 0x280) <= FLOAT_803e8b30) {
        *(float *)(param_10 + 0x7c8) =
             -(float)((double)FLOAT_803e8b28 * param_1 - (double)*(float *)(param_10 + 0x7c8));
        if ((double)FLOAT_803df0c0 <= dVar11) {
          FUN_8000bb38(param_9,0x208);
          uVar5 = FUN_80022264(0x27,0x3c);
          local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          FLOAT_803df0c0 = (float)(local_48 - DOUBLE_803e8b58);
        }
        else {
          FLOAT_803df0c0 = (float)((double)FLOAT_803df0c0 - param_1);
        }
      }
      else {
        dVar10 = (double)(FLOAT_803e8c04 + *(float *)(param_10 + 0x7c8));
        if (dVar10 < dVar11) {
          dVar11 = dVar10;
        }
        *(float *)(param_10 + 0x7c8) = (float)dVar11;
      }
      dVar11 = (double)*(float *)(param_9 + 0x10);
      dVar10 = (double)*(float *)(param_9 + 0x14);
      iVar6 = FUN_80065fcc((double)*(float *)(param_9 + 0xc),dVar11,dVar10,param_9,&local_70,0,0x20)
      ;
      in_f31 = -(double)*(float *)(param_10 + 0x7c8);
      if (1 < iVar6) {
        fVar1 = *(float *)*local_70;
        in_f31 = (double)(float)(in_f31 + (double)(float)((double)fVar1 -
                                                         (double)*(float *)local_70[iVar6 + -1]));
        if ((double)FLOAT_803e8c38 < in_f31) {
          iVar7 = *(int *)(param_9 + 0xb8);
          pcVar8 = *(char **)(iVar7 + 0x35c);
          iVar6 = *pcVar8 + -1;
          if (iVar6 < 0) {
            iVar6 = 0;
          }
          else if (pcVar8[1] < iVar6) {
            iVar6 = (int)pcVar8[1];
          }
          *pcVar8 = (char)iVar6;
          if (**(char **)(iVar7 + 0x35c) < '\x01') {
            FUN_802ab1e0((double)fVar1,dVar11,dVar10,param_4,param_5,param_6,param_7,param_8,param_9
                        );
          }
        }
      }
    }
    if (in_f31 != (double)FLOAT_803e8b3c) {
      dVar11 = -(double)(float)((double)FLOAT_803e8c04 * in_f31 - (double)FLOAT_803e8b78);
      if (dVar11 < (double)FLOAT_803e8bac) {
        dVar11 = (double)FLOAT_803e8bac;
      }
      dVar10 = (double)FUN_802932a4(dVar11,param_1);
      *(float *)(param_9 + 0x24) = (float)((double)*(float *)(param_9 + 0x24) * dVar10);
      dVar11 = (double)FUN_802932a4(dVar11,param_1);
      *(float *)(param_9 + 0x2c) = (float)((double)*(float *)(param_9 + 0x2c) * dVar11);
    }
  }
  dVar11 = FUN_80021434((double)(local_74 - *(float *)(param_10 + 0x890)),(double)FLOAT_803e8c64,
                        (double)FLOAT_803dc074);
  *(float *)(param_10 + 0x890) = (float)((double)*(float *)(param_10 + 0x890) + dVar11);
  dVar11 = FUN_80021434((double)(local_78 - *(float *)(param_10 + 0x894)),(double)FLOAT_803e8c64,
                        (double)FLOAT_803dc074);
  *(float *)(param_10 + 0x894) = (float)((double)*(float *)(param_10 + 0x894) + dVar11);
  if (iVar9 == 0) {
    dVar11 = (double)FUN_802932a4((double)FLOAT_803e8c8c,(double)FLOAT_803dc074);
    *(float *)(param_10 + 0x890) = (float)((double)*(float *)(param_10 + 0x890) * dVar11);
    dVar11 = (double)FUN_802932a4((double)FLOAT_803e8c8c,(double)FLOAT_803dc074);
    *(float *)(param_10 + 0x894) = (float)((double)*(float *)(param_10 + 0x894) * dVar11);
  }
  if ((FLOAT_803e8c84 < *(float *)(param_10 + 0x890)) &&
     (*(float *)(param_10 + 0x890) < FLOAT_803e8b90)) {
    *(float *)(param_10 + 0x890) = FLOAT_803e8b3c;
  }
  if ((FLOAT_803e8c84 < *(float *)(param_10 + 0x894)) &&
     (*(float *)(param_10 + 0x894) < FLOAT_803e8b90)) {
    *(float *)(param_10 + 0x894) = FLOAT_803e8b3c;
  }
  return;
}

