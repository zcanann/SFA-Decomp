// Function: FUN_8005e6dc
// Entry: 8005e6dc
// Size: 464 bytes

int FUN_8005e6dc(int param_1,int *param_2)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int *piVar4;
  int iVar5;
  uint uVar6;
  double dVar7;
  uint local_28;
  uint local_24;
  uint3 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  local_18 = DAT_803e90c8;
  uVar6 = param_2[4];
  uVar3 = *(undefined *)(*param_2 + ((int)uVar6 >> 3));
  iVar5 = *param_2 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_2[4] = uVar6 + 6;
  iVar5 = *(int *)(param_1 + 100) +
          ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7)) & 0x3f) * 0x44;
  FUN_8025c224(0,7,4,5,7);
  piVar4 = (int *)FUN_8004c3cc(iVar5,0);
  FUN_8004c460(*piVar4,0);
  if ((*(uint *)(iVar5 + 0x3c) & 4) == 0) {
    _local_20 = local_18;
    dVar7 = (double)FLOAT_803df84c;
    FUN_8025ca38(dVar7,dVar7,dVar7,dVar7,0,&local_20);
  }
  else {
    FUN_80070540();
  }
  uVar6 = *(uint *)(iVar5 + 0x3c);
  if (((((uVar6 & 1) == 0) && ((uVar6 & 0x40000) == 0)) && ((uVar6 & 0x800) == 0)) &&
     ((uVar6 & 0x1000) == 0)) {
    FUN_80089ab8(0,(byte *)&local_1c,(byte *)((int)&local_1c + 1),(byte *)((int)&local_1c + 2));
    FUN_8025a608(0,1,0,1,0,0,2);
    local_28 = local_1c;
    FUN_8025a2ec(0,&local_28);
  }
  else {
    local_24 = DAT_803dc2a0;
    FUN_8025a2ec(0,&local_24);
    if ((*(uint *)(iVar5 + 0x3c) & 0x40000) == 0) {
      FUN_8025a608(0,1,0,1,0,0,2);
    }
    else {
      FUN_8025a608(0,0,0,1,0,0,2);
    }
  }
  return iVar5;
}

