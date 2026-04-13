// Function: FUN_80154d1c
// Entry: 80154d1c
// Size: 948 bytes

void FUN_80154d1c(ushort *param_1,undefined4 *param_2)

{
  float fVar1;
  int iVar2;
  char cVar3;
  byte bVar4;
  float *pfVar5;
  double dVar6;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  pfVar5 = (float *)*param_2;
  if ((param_2[0xb7] & 0x80000000) != 0) {
    FUN_8000bb38((uint)param_1,0x4c0);
  }
  if ((((param_2[0xb7] & 0x2000) != 0) &&
      (((iVar2 = FUN_80010340((double)FLOAT_803e3628,pfVar5), iVar2 != 0 || (pfVar5[4] != 0.0)) &&
       (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar3 != '\0')))) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3648,*param_2,param_1,&DAT_803dc938,0xffffffff),
     cVar3 != '\0')) {
    param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
  }
  FUN_80035eec((int)param_1,0xe,1,0);
  iVar2 = FUN_8002bac4();
  bVar4 = FUN_80296ba8(iVar2);
  local_38 = *(float *)(param_2[0xa7] + 0xc) - *(float *)(param_1 + 6);
  local_34 = FLOAT_803e3628;
  local_30 = *(float *)(param_2[0xa7] + 0x14) - *(float *)(param_1 + 10);
  if ((param_2[0xd0] != 0) && (iVar2 = FUN_8002bac4(), param_2[0xd0] == iVar2)) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    param_2[0xc9] = FLOAT_803e3628;
  }
  local_28 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar6 = (double)FUN_80294504();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar2 = (int)-(float)((double)FLOAT_803e3654 * dVar6 -
                       (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_18 = (longlong)iVar2;
  param_1[1] = (ushort)iVar2;
  fVar1 = FLOAT_803e3628;
  if (bVar4 == 0) {
    *(float *)(param_1 + 0x12) = FLOAT_803e3628;
    *(float *)(param_1 + 0x16) = fVar1;
    FUN_8014d3f4((short *)param_1,param_2,10,0);
  }
  else {
    FUN_8014caf0((double)FLOAT_803e3638,(double)FLOAT_803e364c,(double)FLOAT_803e364c,(int)param_1,
                 (int)param_2,&local_38,'\x01');
    FUN_8014d194((double)FLOAT_803e365c,(double)FLOAT_803e362c,param_1,(int)param_2,0xf,'\0');
  }
  fVar1 = FLOAT_803e3628;
  if ((param_2[0xb7] & 0x40000000) != 0) {
    if (FLOAT_803e3628 == (float)param_2[0xca]) {
      if (bVar4 == 0) {
        if (*(float *)(param_1 + 0x4c) <= FLOAT_803e363c) {
          param_2[0xca] = FLOAT_803e367c;
        }
        else {
          param_2[0xca] = FLOAT_803e3678;
          *(char *)((int)param_2 + 0x33b) = *(char *)((int)param_2 + 0x33b) + '\x01';
        }
      }
      else if ((double)*(float *)(param_1 + 0x4c) <= DOUBLE_803e3660) {
        FUN_8000bb38((uint)param_1,0x24c);
        param_2[0xc2] = FLOAT_803e366c;
      }
      else {
        FUN_8000bb38((uint)param_1,0x24b);
        param_2[0xc2] = FLOAT_803e3668;
      }
    }
    else {
      param_2[0xca] = (float)param_2[0xca] - FLOAT_803dc074;
      if ((float)param_2[0xca] <= fVar1) {
        param_2[0xca] = fVar1;
        if ((double)*(float *)(param_1 + 0x4c) <= DOUBLE_803e3660) {
          FUN_8000bb38((uint)param_1,0x24c);
          param_2[0xc2] = FLOAT_803e364c;
        }
        else {
          FUN_8000bb38((uint)param_1,0x24b);
          param_2[0xc2] = FLOAT_803e3668;
        }
      }
    }
  }
  *(char *)((int)param_2 + 0x33a) = *(char *)((int)param_2 + 0x33a) + '\x01';
  local_18 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar6 = (double)FUN_80294504();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar2 = (int)((double)FLOAT_803e3654 * dVar6 +
               (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_28 = (longlong)iVar2;
  param_1[1] = (ushort)iVar2;
  FUN_801547d4(param_1,(int)param_2);
  return;
}

