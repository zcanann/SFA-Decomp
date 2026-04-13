// Function: FUN_8005f6d4
// Entry: 8005f6d4
// Size: 968 bytes

int FUN_8005f6d4(char param_1,int param_2,int *param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  undefined4 uVar4;
  char cVar5;
  int iVar6;
  uint uVar7;
  double dVar8;
  uint local_28;
  uint local_24;
  uint3 local_20;
  undefined4 uStack_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  uVar4 = DAT_803e90c4;
  local_14 = DAT_803e90c4;
  uVar7 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar7 >> 3));
  iVar6 = *param_3 + ((int)uVar7 >> 3);
  uVar1 = *(undefined *)(iVar6 + 1);
  uVar2 = *(undefined *)(iVar6 + 2);
  param_3[4] = uVar7 + 6;
  iVar6 = *(int *)(param_2 + 100) +
          ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar7 & 7)) & 0x3f) * 0x44;
  if (param_1 != '\0') {
    if ((*(uint *)(iVar6 + 0x3c) & 4) == 0) {
      _local_20 = uVar4;
      dVar8 = (double)FLOAT_803df84c;
      FUN_8025ca38(dVar8,dVar8,dVar8,dVar8,0,&local_20);
    }
    else {
      FUN_80070540();
    }
    if (((iVar6 == 0) || ((*(uint *)(iVar6 + 0x3c) & 0x80000000) == 0)) &&
       ((iVar6 == 0 ||
        (((*(uint *)(iVar6 + 0x3c) & 0x20000) == 0 ||
         (uVar7 = FUN_8011853c(0,(int *)0x0,0), (uVar7 & 0xff) == 0)))))) {
      FUN_80052a6c();
      if ((*(uint *)(iVar6 + 0x3c) & 0x80) == 0) {
        FUN_8005f35c(iVar6);
      }
      else {
        FUN_8004dbd0(iVar6);
      }
      if (((*(uint *)(iVar6 + 0x3c) & 0x20) == 0) || (DAT_803ddab4 == 0)) {
        if ((*(uint *)(iVar6 + 0x3c) & 0x40) == 0) {
          cVar5 = FUN_8004c3c4();
          if (cVar5 != '\0') {
            FUN_80070658((undefined *)&uStack_1c);
            FUN_8004e974(&uStack_1c);
          }
        }
        else {
          FUN_8004e278();
        }
      }
      else {
        FUN_8004ff1c(DAT_803ddab4,(float *)&DAT_80382c68);
      }
      uVar7 = *(uint *)(iVar6 + 0x3c);
      if (((uVar7 & 0x40000000) == 0) && ((uVar7 & 0x20000000) == 0)) {
        if (((uVar7 & 0x400) == 0) || ((uVar7 & 0x80) != 0)) {
          FUN_8025cce8(0,1,0,5);
          FUN_8007048c(1,3,1);
          FUN_80070434(1);
          FUN_8025c754(7,0,0,7,0);
        }
        else {
          FUN_8025cce8(0,1,0,5);
          FUN_8007048c(1,3,1);
          FUN_80070434(0);
          FUN_8025c754(4,0,0,4,0);
        }
      }
      else {
        FUN_8025cce8(1,4,5,5);
        FUN_8007048c(1,3,0);
        FUN_80070434(1);
        FUN_8025c754(7,0,0,7,0);
      }
      uVar7 = *(uint *)(iVar6 + 0x3c);
      if (((((uVar7 & 1) == 0) && ((uVar7 & 0x40000) == 0)) && ((uVar7 & 0x800) == 0)) &&
         ((uVar7 & 0x1000) == 0)) {
        FUN_80089ab8(0,(byte *)&local_18,(byte *)((int)&local_18 + 1),(byte *)((int)&local_18 + 2));
        FUN_8025a608(0,1,0,1,0,0,2);
        local_28 = local_18;
        FUN_8025a2ec(0,&local_28);
      }
      else {
        local_24 = DAT_803dc29c;
        FUN_8025a2ec(0,&local_24);
        if ((*(uint *)(iVar6 + 0x3c) & 0x40000) == 0) {
          FUN_8025a608(0,1,0,1,0,0,2);
        }
        else {
          FUN_8025a608(0,0,0,1,0,0,2);
        }
      }
      if ((*(uint *)(iVar6 + 0x3c) & 8) == 0) {
        FUN_80259288(0);
      }
      else {
        FUN_80259288(2);
      }
    }
  }
  return iVar6;
}

