// Function: FUN_80179c88
// Entry: 80179c88
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x80179d94) */

void FUN_80179c88(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  
  iVar8 = *(int *)(param_9 + 0x5c);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  *(undefined *)(iVar8 + 0x275) = 0;
  iVar4 = FUN_8002bac4();
  iVar5 = FUN_8002ba84();
  if ((((iVar4 == 0) || ((*(ushort *)(iVar4 + 0xb0) & 0x1000) != 0)) || (iVar5 == 0)) ||
     ((uVar3 = countLeadingZeros((uint)*(ushort *)(iVar5 + 0xb0)), (uVar3 >> 5 & 0x1000) != 0 ||
      (uVar3 = FUN_80020078(0xd00), uVar3 != 0)))) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    return;
  }
  cVar1 = *(char *)(iVar8 + 0x274);
  if (((cVar1 == '\x03') || (cVar1 == '\x02')) || (cVar1 == '\x01')) {
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) + FLOAT_803dc074;
    param_1 = (double)*(float *)(iVar8 + 0x26c);
    if ((double)FLOAT_803e4340 <= param_1) {
      *(float *)(iVar8 + 0x26c) = FLOAT_803e4334;
      *(undefined *)(iVar8 + 0x274) = 5;
    }
  }
  bVar2 = *(byte *)(iVar8 + 0x274);
  if (bVar2 == 3) {
    uVar6 = FUN_80179f40(param_9);
    *(char *)(iVar8 + 0x274) = (char)uVar6;
    return;
  }
  if (bVar2 < 3) {
    if (bVar2 == 1) {
      FUN_80179f40(param_9);
    }
    else if (bVar2 == 0) {
      FUN_80179864(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                   iVar8,param_11,param_12,param_13,param_14,param_15,param_16);
      goto LAB_80179e98;
    }
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    uVar7 = 0;
    uVar3 = FUN_80014b50(0);
    if ((((uVar3 & 0x100) == 0) && (*(int *)(param_9 + 0x7c) == 0)) &&
       (iVar4 = FUN_8003811c((int)param_9), iVar4 != 0)) {
      FUN_80035ff8((int)param_9);
      uVar7 = 1;
    }
    *(undefined *)(iVar8 + 0x2c9) = uVar7;
    if (*(char *)(iVar8 + 0x2c9) != '\0') {
      *(undefined *)(iVar8 + 0x2c8) = 0;
      *(undefined *)(iVar8 + 0x2c9) = 0;
      *(undefined *)(iVar8 + 0x274) = 0;
    }
  }
  else if (bVar2 == 5) {
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) + FLOAT_803dc074;
    dVar10 = (double)*(float *)(iVar8 + 0x26c);
    dVar9 = (double)FLOAT_803e433c;
    if (dVar9 <= dVar10) {
      FUN_8002cc9c(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    *(char *)(param_9 + 0x1b) =
         -1 - (char)(int)((double)(float)((double)FLOAT_803e4344 * dVar10) / dVar9);
  }
LAB_80179e98:
  if (*(char *)(*(int *)(param_9 + 0x5c) + 0x25b) == '\x01') {
    (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,iVar8);
    (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar8);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar8);
  }
  else {
    (**(code **)(*DAT_803dd728 + 0x20))(param_9);
  }
  return;
}

