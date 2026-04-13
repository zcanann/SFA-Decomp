// Function: FUN_8005dcb4
// Entry: 8005dcb4
// Size: 860 bytes

void FUN_8005dcb4(void)

{
  byte bVar2;
  float *pfVar1;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined4 local_88;
  uint local_84;
  undefined4 local_80;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  float afStack_70 [28];
  
  FUN_80286830();
  FUN_8005d3ec();
  piVar6 = &DAT_8037ed20;
  for (iVar5 = 0; iVar5 < DAT_803ddab0; iVar5 = iVar5 + 1) {
    switch(piVar6[3]) {
    case 0:
      FUN_8009e2c0();
      FUN_8005dbc4((ushort *)*piVar6);
      FUN_8009e2c0();
      break;
    case 1:
      iVar3 = *piVar6;
      FUN_8002b660(iVar3);
      iVar4 = FUN_8002bac4();
      if (iVar3 == iVar4) {
        bVar2 = FUN_80296434(iVar3);
        if (bVar2 == 0) {
          FUN_802b5638(iVar3,'\x01','\x01');
        }
      }
      else {
        FUN_800415ac(iVar3);
      }
      break;
    case 2:
      FUN_8000f9d4();
      FUN_80062614();
      FUN_8000f7a0();
      break;
    case 3:
      FUN_8000f9d4();
      iVar4 = FUN_8002b660(*piVar6);
      FUN_800617d0((ushort *)*piVar6,iVar4);
      FUN_8000f7a0();
      break;
    case 4:
      iVar4 = piVar6[1];
      FUN_8025a608(0,1,0,1,0,0,2);
      FUN_8025a608(2,0,0,1,0,0,2);
      FUN_80089ab8(0,(byte *)&local_78,(byte *)((int)&local_78 + 1),(byte *)((int)&local_78 + 2));
      local_74 = local_78;
      FUN_8025a2ec(0,&local_74);
      FUN_8025a5bc(1);
      pfVar1 = (float *)FUN_8000f56c();
      FUN_80247618(pfVar1,(float *)(iVar4 + 0xc),afStack_70);
      FUN_8005fc74(iVar4,afStack_70);
      FUN_8005da10(*piVar6,piVar6[1],afStack_70);
      break;
    case 5:
      iVar4 = piVar6[1];
      FUN_8025a608(0,1,0,1,0,0,2);
      FUN_8025a608(2,0,0,1,0,0,2);
      FUN_80089ab8(0,(byte *)&local_80,(byte *)((int)&local_80 + 1),(byte *)((int)&local_80 + 2));
      local_7c = local_80;
      FUN_8025a2ec(0,&local_7c);
      FUN_8025a5bc(1);
      pfVar1 = (float *)FUN_8000f56c();
      FUN_80247618(pfVar1,(float *)(iVar4 + 0xc),afStack_70);
      FUN_8005fc74(iVar4,afStack_70);
      FUN_8005d818(*piVar6,piVar6[1],afStack_70);
      break;
    case 6:
      iVar4 = piVar6[1];
      FUN_8025a608(0,1,0,1,0,0,2);
      FUN_8025a608(2,0,0,1,0,0,2);
      FUN_80089ab8(0,(byte *)&local_88,(byte *)((int)&local_88 + 1),(byte *)((int)&local_88 + 2));
      local_84 = local_88;
      FUN_8025a2ec(0,&local_84);
      FUN_8025a5bc(1);
      pfVar1 = (float *)FUN_8000f56c();
      FUN_80247618(pfVar1,(float *)(iVar4 + 0xc),afStack_70);
      FUN_8005fc74(iVar4,afStack_70);
      FUN_8005d668(*piVar6,piVar6[1],afStack_70);
      break;
    case 7:
      FUN_8009e3c8();
      break;
    case 8:
      FUN_8006f67c();
      break;
    case 9:
      (**(code **)(*DAT_803dd718 + 0xc))(0,0);
    }
    piVar6 = piVar6 + 4;
  }
  FUN_8028687c();
  return;
}

