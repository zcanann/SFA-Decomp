// Function: FUN_8005e560
// Entry: 8005e560
// Size: 464 bytes

int FUN_8005e560(int param_1,int *param_2)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  double dVar7;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  local_18 = DAT_803e8448;
  uVar6 = param_2[4];
  uVar3 = *(undefined *)(*param_2 + ((int)uVar6 >> 3));
  iVar5 = *param_2 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_2[4] = uVar6 + 6;
  iVar5 = *(int *)(param_1 + 100) +
          ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7)) & 0x3f) * 0x44;
  FUN_8025bac0(0,7,4,5,7);
  puVar4 = (undefined4 *)FUN_8004c250(iVar5,0);
  FUN_8004c2e4(*puVar4,0);
  if ((*(uint *)(iVar5 + 0x3c) & 4) == 0) {
    local_20 = local_18;
    dVar7 = (double)FLOAT_803debcc;
    FUN_8025c2d4(dVar7,dVar7,dVar7,dVar7,0,&local_20);
  }
  else {
    FUN_800703c4();
  }
  uVar6 = *(uint *)(iVar5 + 0x3c);
  if (((((uVar6 & 1) == 0) && ((uVar6 & 0x40000) == 0)) && ((uVar6 & 0x800) == 0)) &&
     ((uVar6 & 0x1000) == 0)) {
    FUN_8008982c(0,&local_1c,(int)&local_1c + 1,(int)&local_1c + 2);
    FUN_80259ea4(0,1,0,1,0,0,2);
    local_28 = local_1c;
    FUN_80259b88(0,&local_28);
  }
  else {
    local_24 = DAT_803db640;
    FUN_80259b88(0,&local_24);
    if ((*(uint *)(iVar5 + 0x3c) & 0x40000) == 0) {
      FUN_80259ea4(0,1,0,1,0,0,2);
    }
    else {
      FUN_80259ea4(0,0,0,1,0,0,2);
    }
  }
  return iVar5;
}

