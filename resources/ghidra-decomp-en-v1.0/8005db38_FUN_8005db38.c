// Function: FUN_8005db38
// Entry: 8005db38
// Size: 860 bytes

void FUN_8005db38(void)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined auStack112 [112];
  
  FUN_802860cc();
  FUN_8005d270();
  piVar5 = &DAT_8037e0c0;
  for (iVar4 = 0; iVar4 < DAT_803dce30; iVar4 = iVar4 + 1) {
    switch(piVar5[3]) {
    case 0:
      FUN_8009e034(*piVar5,0);
      FUN_8005da48(*piVar5);
      FUN_8009e034(*piVar5,1);
      break;
    case 1:
      iVar2 = *piVar5;
      FUN_8002b588(iVar2);
      iVar3 = FUN_8002b9ec();
      if (iVar2 == iVar3) {
        iVar3 = FUN_80295cd4(iVar2);
        if (iVar3 == 0) {
          FUN_802b4ed8(iVar2,1,1);
        }
      }
      else {
        FUN_800414b4(iVar2);
      }
      break;
    case 2:
      FUN_8000f9b4();
      FUN_80062498(*piVar5,0,0,DAT_803db410);
      FUN_8000f780();
      break;
    case 3:
      FUN_8000f9b4();
      uVar1 = FUN_8002b588(*piVar5);
      FUN_80061654(*piVar5,uVar1);
      FUN_8000f780();
      break;
    case 4:
      iVar3 = piVar5[1];
      FUN_80259ea4(0,1,0,1,0,0,2);
      FUN_80259ea4(2,0,0,1,0,0,2);
      FUN_8008982c(0,&local_78,(int)&local_78 + 1,(int)&local_78 + 2);
      local_74 = local_78;
      FUN_80259b88(0,&local_74);
      FUN_80259e58(1);
      uVar1 = FUN_8000f54c();
      FUN_80246eb4(uVar1,iVar3 + 0xc,auStack112);
      FUN_8005faf8(iVar3,auStack112);
      FUN_8005d894(*piVar5,piVar5[1],auStack112);
      break;
    case 5:
      iVar3 = piVar5[1];
      FUN_80259ea4(0,1,0,1,0,0,2);
      FUN_80259ea4(2,0,0,1,0,0,2);
      FUN_8008982c(0,&local_80,(int)&local_80 + 1,(int)&local_80 + 2);
      local_7c = local_80;
      FUN_80259b88(0,&local_7c);
      FUN_80259e58(1);
      uVar1 = FUN_8000f54c();
      FUN_80246eb4(uVar1,iVar3 + 0xc,auStack112);
      FUN_8005faf8(iVar3,auStack112);
      FUN_8005d69c(*piVar5,piVar5[1],auStack112);
      break;
    case 6:
      iVar3 = piVar5[1];
      FUN_80259ea4(0,1,0,1,0,0,2);
      FUN_80259ea4(2,0,0,1,0,0,2);
      FUN_8008982c(0,&local_88,(int)&local_88 + 1,(int)&local_88 + 2);
      local_84 = local_88;
      FUN_80259b88(0,&local_84);
      FUN_80259e58(1);
      uVar1 = FUN_8000f54c();
      FUN_80246eb4(uVar1,iVar3 + 0xc,auStack112);
      FUN_8005faf8(iVar3,auStack112);
      FUN_8005d4ec(*piVar5,piVar5[1],auStack112);
      break;
    case 7:
      FUN_8009e13c(*piVar5,piVar5[1]);
      break;
    case 8:
      FUN_8006f500();
      break;
    case 9:
      (**(code **)(*DAT_803dca98 + 0xc))(0,0);
    }
    piVar5 = piVar5 + 4;
  }
  FUN_80286118();
  return;
}

