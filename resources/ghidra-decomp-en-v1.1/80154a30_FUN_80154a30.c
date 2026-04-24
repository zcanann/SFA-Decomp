// Function: FUN_80154a30
// Entry: 80154a30
// Size: 748 bytes

void FUN_80154a30(ushort *param_1,undefined4 *param_2)

{
  int iVar1;
  char cVar3;
  uint uVar2;
  float *pfVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  pfVar4 = (float *)*param_2;
  *(undefined *)((int)param_2 + 0x33b) = 0;
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  if ((param_2[0xb7] & 0x2000) != 0) {
    iVar1 = FUN_80010340((double)(float)param_2[0xbf],pfVar4);
    if ((((iVar1 != 0) || (pfVar4[4] != 0.0)) &&
        (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e3648,*param_2,param_1,&DAT_803dc938,0xffffffff),
       cVar3 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    local_38 = pfVar4[0x1a] - *(float *)(param_1 + 6);
    local_34 = FLOAT_803e3628;
    local_30 = pfVar4[0x1c] - *(float *)(param_1 + 10);
    FUN_8014caf0((double)FLOAT_803e3638,(double)FLOAT_803e364c,(double)FLOAT_803e364c,(int)param_1,
                 (int)param_2,&local_38,'\x01');
    param_2[0xc9] = (float)param_2[0xc9] + FLOAT_803dc074;
    if (FLOAT_803e3650 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = FLOAT_803e3628;
    }
  }
  local_28 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar5 = (double)FUN_80294504();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar1 = (int)-(float)((double)FLOAT_803e3654 * dVar5 -
                       (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_18 = (longlong)iVar1;
  param_1[1] = (ushort)iVar1;
  FUN_8014d194((double)FLOAT_803e365c,(double)FLOAT_803e362c,param_1,(int)param_2,0xf,'\0');
  if ((param_2[0xb7] & 0x40000000) != 0) {
    if (DOUBLE_803e3660 <= (double)*(float *)(param_1 + 0x4c)) {
      uVar2 = FUN_80022264(0,0x3c);
    }
    else {
      uVar2 = FUN_80022264(0,200);
    }
    if ((uVar2 & 0xff) == 0) {
      if ((double)*(float *)(param_1 + 0x4c) <= DOUBLE_803e3660) {
        FUN_8000bb38((uint)param_1,0x24c);
        param_2[0xc2] = FLOAT_803e366c;
      }
      else {
        FUN_8000bb38((uint)param_1,0x24b);
        param_2[0xc2] = FLOAT_803e3668;
      }
    }
  }
  *(char *)((int)param_2 + 0x33a) = *(char *)((int)param_2 + 0x33a) + '\x01';
  local_18 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar5 = (double)FUN_80294504();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar1 = (int)((double)FLOAT_803e3654 * dVar5 +
               (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_28 = (longlong)iVar1;
  param_1[1] = (ushort)iVar1;
  FUN_801547d4(param_1,(int)param_2);
  return;
}

