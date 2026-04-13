// Function: FUN_80039ab8
// Entry: 80039ab8
// Size: 404 bytes

/* WARNING: Removing unreachable block (ram,0x80039c2c) */
/* WARNING: Removing unreachable block (ram,0x80039ac8) */

undefined4 FUN_80039ab8(int param_1,int param_2)

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  local_48 = FLOAT_803df658;
  local_44 = FLOAT_803df658;
  local_40 = FLOAT_803df65c;
  local_3c = FLOAT_803df660;
  if ((int)*(short *)(param_1 + 0x14) == (int)*(short *)(param_1 + 0x16)) {
    uVar1 = 1;
  }
  else {
    uStack_34 = (int)*(short *)(param_2 + 2) ^ 0x80000000;
    local_38 = 0x43300000;
    uStack_2c = (int)*(short *)(param_1 + 0x16) ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0x14) ^ 0x80000000);
    local_20 = 0x43300000;
    dVar3 = (double)(((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df650) -
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)) /
                    ((float)(local_28 - DOUBLE_803df650) -
                    (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)));
    dVar2 = (double)FLOAT_803df61c;
    if ((dVar3 <= dVar2) && (dVar2 = dVar3, dVar3 < (double)FLOAT_803df624)) {
      dVar2 = (double)FLOAT_803df624;
    }
    uStack_1c = uStack_2c;
    dVar3 = FUN_80010de0(dVar2,&local_48,(float *)0x0);
    if (*(short *)(param_1 + 0x14) < *(short *)(param_1 + 0x16)) {
      dVar3 = -dVar3;
    }
    *(short *)(param_2 + 2) =
         (short)(int)(dVar3 * (double)FLOAT_803dc074 +
                     (double)(float)((double)CONCAT44(0x43300000,
                                                      (int)*(short *)(param_2 + 2) ^ 0x80000000) -
                                    DOUBLE_803df650));
    if ((((double)FLOAT_803df61c == dVar2) || (0x1ffe < *(short *)(param_2 + 2))) ||
       (*(short *)(param_2 + 2) < -0x1ffe)) {
      *(undefined2 *)(param_2 + 2) = *(undefined2 *)(param_1 + 0x14);
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  return uVar1;
}

