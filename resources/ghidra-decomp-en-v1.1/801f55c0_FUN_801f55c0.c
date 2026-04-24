// Function: FUN_801f55c0
// Entry: 801f55c0
// Size: 1088 bytes

void FUN_801f55c0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  char cVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  double dVar9;
  double dVar10;
  undefined8 local_20;
  
  iVar8 = *(int *)(param_9 + 0x5c);
  iVar4 = FUN_8002bac4();
  if (*(byte *)(param_9 + 0x1b) < 0xff) {
    param_3 = (double)FLOAT_803e6b74;
    iVar3 = (int)(param_3 * (double)FLOAT_803dc074 +
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_9 + 0x1b) ^ 0x80000000)
                                - DOUBLE_803e6b68));
    if (0xff < iVar3) {
      iVar3 = 0xff;
    }
    *(char *)(param_9 + 0x1b) = (char)iVar3;
  }
  if (FLOAT_803e6b4c < *(float *)(iVar8 + 0x40)) {
    *(float *)(iVar8 + 0x40) = *(float *)(iVar8 + 0x40) - FLOAT_803e6b4c;
    if (*(byte *)(iVar8 + 0x68) < 4) {
      FUN_801f538c(param_9,iVar8);
    }
    else {
      *(byte *)(iVar8 + 0x68) = *(byte *)(iVar8 + 0x68) + 1;
    }
    *(undefined4 *)(iVar8 + 4) = *(undefined4 *)(iVar8 + 8);
    *(undefined4 *)(iVar8 + 0x14) = *(undefined4 *)(iVar8 + 0x18);
    *(undefined4 *)(iVar8 + 0x24) = *(undefined4 *)(iVar8 + 0x28);
    *(undefined4 *)(iVar8 + 8) = *(undefined4 *)(iVar8 + 0xc);
    *(undefined4 *)(iVar8 + 0x18) = *(undefined4 *)(iVar8 + 0x1c);
    *(undefined4 *)(iVar8 + 0x28) = *(undefined4 *)(iVar8 + 0x2c);
    *(undefined4 *)(iVar8 + 0xc) = *(undefined4 *)(iVar8 + 0x10);
    *(undefined4 *)(iVar8 + 0x1c) = *(undefined4 *)(iVar8 + 0x20);
    *(undefined4 *)(iVar8 + 0x2c) = *(undefined4 *)(iVar8 + 0x30);
    uVar5 = FUN_80022264(0xa0,0xb4);
    local_20 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(iVar8 + 0x44) = FLOAT_803e6b70 * (float)(local_20 - DOUBLE_803e6b68);
    *(undefined4 *)(iVar8 + 0x10) = *(undefined4 *)(iVar8 + 0x34);
    *(undefined4 *)(iVar8 + 0x20) = *(undefined4 *)(iVar8 + 0x38);
    *(undefined4 *)(iVar8 + 0x30) = *(undefined4 *)(iVar8 + 0x3c);
  }
  dVar9 = FUN_80010f00((double)*(float *)(iVar8 + 0x40),(float *)(iVar8 + 4),(float *)0x0);
  *(float *)(param_9 + 6) = (float)dVar9;
  dVar9 = FUN_80010f00((double)*(float *)(iVar8 + 0x40),(float *)(iVar8 + 0x14),(float *)0x0);
  *(float *)(param_9 + 8) = (float)dVar9;
  dVar9 = FUN_80010f00((double)*(float *)(iVar8 + 0x40),(float *)(iVar8 + 0x24),(float *)0x0);
  *(float *)(param_9 + 10) = (float)dVar9;
  *(float *)(iVar8 + 0x40) = *(float *)(iVar8 + 0x44) * FLOAT_803dc074 + *(float *)(iVar8 + 0x40);
  iVar3 = FUN_80021884();
  *param_9 = (short)iVar3;
  if ((*(char *)(iVar8 + 0x66) == '\x01') || (*(char *)(iVar8 + 0x66) == '\x04')) {
    uVar6 = 0xffffffff;
    uVar7 = 0;
    iVar3 = *DAT_803dd708;
    (**(code **)(iVar3 + 8))(param_9,0x1a0,0,1);
  }
  else {
    uVar6 = 0xffffffff;
    uVar7 = 0;
    iVar3 = *DAT_803dd708;
    (**(code **)(iVar3 + 8))(param_9,0x1bd,0,1);
  }
  dVar9 = (double)FUN_80021754((float *)(iVar4 + 0x18),(float *)(*(int *)(param_9 + 0x26) + 8));
  fVar2 = FLOAT_803e6b80;
  if ((double)*(float *)(iVar8 + 0x4c) <= dVar9) {
    dVar10 = (double)*(float *)(iVar8 + 0x48);
    dVar9 = (double)FLOAT_803e6b80;
    if ((dVar9 < dVar10) &&
       (*(float *)(iVar8 + 0x48) = (float)(dVar10 - (double)FLOAT_803e6b7c),
       (double)*(float *)(iVar8 + 0x48) < dVar9)) {
      *(float *)(iVar8 + 0x48) = fVar2;
    }
  }
  else {
    cVar1 = *(char *)(iVar8 + 0x66);
    if (cVar1 == '\x04') {
      uVar6 = 0xffffffff;
      uVar7 = 0;
      iVar3 = *DAT_803dd708;
      (**(code **)(iVar3 + 8))(param_9,0x19f,0,1);
    }
    else if (cVar1 == '\x03') {
      uVar6 = 0xffffffff;
      uVar7 = 0;
      iVar3 = *DAT_803dd708;
      (**(code **)(iVar3 + 8))(param_9,0x1bc,0,1);
    }
    else if (cVar1 == '\x05') {
      uVar6 = 0xffffffff;
      uVar7 = 0;
      iVar3 = *DAT_803dd708;
      (**(code **)(iVar3 + 8))(param_9,0x1bc,0,1);
    }
    fVar2 = FLOAT_803e6b78;
    dVar10 = (double)*(float *)(iVar8 + 0x48);
    dVar9 = (double)FLOAT_803e6b78;
    if ((dVar10 < dVar9) &&
       (*(float *)(iVar8 + 0x48) = (float)(dVar10 + (double)FLOAT_803e6b7c),
       dVar9 < (double)*(float *)(iVar8 + 0x48))) {
      *(float *)(iVar8 + 0x48) = fVar2;
    }
  }
  fVar2 = *(float *)(param_9 + 8) - *(float *)(iVar4 + 0x10);
  if (((((*(byte *)(iVar8 + 0x7c) & 1) == 0) && (fVar2 < FLOAT_803e6b84)) &&
      (FLOAT_803e6b5c < fVar2)) &&
     (dVar9 = FUN_80021730((float *)(param_9 + 0xc),(float *)(iVar4 + 0x18)),
     dVar9 < (double)FLOAT_803e6b88)) {
    *(byte *)(iVar8 + 0x7c) = *(byte *)(iVar8 + 0x7c) | 1;
    uVar5 = FUN_80020078(0xd28);
    if (uVar5 == 0) {
      *(undefined2 *)(iVar8 + 0x80) = 0xffff;
      FUN_800379bc(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,0x7000a,
                   (uint)param_9,iVar8 + 0x80,uVar6,uVar7,iVar3,in_r10);
      FUN_800201ac(0xd28,1);
    }
    else {
      param_9[3] = param_9[3] | 0x4000;
      *(float *)(*(int *)(param_9 + 0x5c) + 0x70) = FLOAT_803e6b40;
      FUN_80020000(0x13d);
      FUN_80020000(0x5d6);
      FUN_8000bb38((uint)param_9,0x49);
    }
  }
  return;
}

