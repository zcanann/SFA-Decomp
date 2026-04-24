// Function: FUN_8005f558
// Entry: 8005f558
// Size: 968 bytes

int FUN_8005f558(char param_1,int param_2,int *param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  undefined4 uVar4;
  char cVar5;
  int iVar6;
  uint uVar7;
  double dVar8;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined auStack28 [4];
  undefined4 local_18;
  undefined4 local_14;
  
  uVar4 = DAT_803e8444;
  local_14 = DAT_803e8444;
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
      local_20 = uVar4;
      dVar8 = (double)FLOAT_803debcc;
      FUN_8025c2d4(dVar8,dVar8,dVar8,dVar8,0,&local_20);
    }
    else {
      FUN_800703c4();
    }
    if (((iVar6 == 0) || ((*(uint *)(iVar6 + 0x3c) & 0x80000000) == 0)) &&
       ((iVar6 == 0 ||
        (((*(uint *)(iVar6 + 0x3c) & 0x20000) == 0 || (cVar5 = FUN_80118294(0,0,0), cVar5 == '\0')))
        ))) {
      FUN_800528f0();
      if ((*(uint *)(iVar6 + 0x3c) & 0x80) == 0) {
        FUN_8005f1e0(iVar6,0x80);
      }
      else {
        FUN_8004da54(iVar6);
      }
      if (((*(uint *)(iVar6 + 0x3c) & 0x20) == 0) || (DAT_803dce34 == 0)) {
        if ((*(uint *)(iVar6 + 0x3c) & 0x40) == 0) {
          cVar5 = FUN_8004c248();
          if (cVar5 != '\0') {
            FUN_800704dc(auStack28);
            FUN_8004e7f8(auStack28);
          }
        }
        else {
          FUN_8004e0fc();
        }
      }
      else {
        FUN_8004fda0(DAT_803dce34,&DAT_80382008,&DAT_803db638);
      }
      uVar7 = *(uint *)(iVar6 + 0x3c);
      if (((uVar7 & 0x40000000) == 0) && ((uVar7 & 0x20000000) == 0)) {
        if (((uVar7 & 0x400) == 0) || ((uVar7 & 0x80) != 0)) {
          FUN_8025c584(0,1,0,5);
          FUN_80070310(1,3,1);
          FUN_800702b8(1);
          FUN_8025bff0(7,0,0,7,0);
        }
        else {
          FUN_8025c584(0,1,0,5);
          FUN_80070310(1,3,1);
          FUN_800702b8(0);
          FUN_8025bff0(4,0,0,4,0);
        }
      }
      else {
        FUN_8025c584(1,4,5,5);
        FUN_80070310(1,3,0);
        FUN_800702b8(1);
        FUN_8025bff0(7,0,0,7,0);
      }
      uVar7 = *(uint *)(iVar6 + 0x3c);
      if (((((uVar7 & 1) == 0) && ((uVar7 & 0x40000) == 0)) && ((uVar7 & 0x800) == 0)) &&
         ((uVar7 & 0x1000) == 0)) {
        FUN_8008982c(0,&local_18,(int)&local_18 + 1,(int)&local_18 + 2);
        FUN_80259ea4(0,1,0,1,0,0,2);
        local_28 = local_18;
        FUN_80259b88(0,&local_28);
      }
      else {
        local_24 = DAT_803db63c;
        FUN_80259b88(0,&local_24);
        if ((*(uint *)(iVar6 + 0x3c) & 0x40000) == 0) {
          FUN_80259ea4(0,1,0,1,0,0,2);
        }
        else {
          FUN_80259ea4(0,0,0,1,0,0,2);
        }
      }
      if ((*(uint *)(iVar6 + 0x3c) & 8) == 0) {
        FUN_80258b24(0);
      }
      else {
        FUN_80258b24(2);
      }
    }
  }
  return iVar6;
}

