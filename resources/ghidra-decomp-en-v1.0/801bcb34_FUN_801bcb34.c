// Function: FUN_801bcb34
// Entry: 801bcb34
// Size: 1804 bytes

void FUN_801bcb34(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar3 = FUN_802860d0();
  iVar9 = *(int *)(iVar3 + 0xb8);
  iVar8 = *(int *)(iVar3 + 0x4c);
  FUN_8002b9ec();
  iVar7 = *(int *)(iVar9 + 0x40c);
  *(undefined2 *)(iVar9 + 0x402) = 0;
  (**(code **)(*DAT_803dcaac + 0x50))(0x1c,5,0);
  if (*(int *)(iVar3 + 0xf4) == 0) {
    FUN_80114bb0(iVar3,param_3,&DAT_803ac9dc,1,1);
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      switch(*(undefined *)(param_3 + iVar6 + 0x81)) {
      case 1:
        (**(code **)(*DAT_803dcab4 + 0xc))(iVar3,0x800,0,100,0);
        (**(code **)(*DAT_803dcab4 + 0xc))(iVar3,0x800,0,100,0);
        (**(code **)(*DAT_803dcab4 + 0xc))(iVar3,0x7ff,0,100,0);
        (**(code **)(*DAT_803dcab4 + 0xc))(iVar3,0x7ff,0,100,0);
        FUN_8002b588(iVar3);
        FUN_8002843c();
        FUN_8000a518(0x27,1);
        break;
      case 2:
        *(undefined2 *)(iVar9 + 0x402) = 1;
        *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) & 0xf7;
        *(byte *)(iVar3 + 0xaf) = *(byte *)(iVar3 + 0xaf) | 0x80;
        (**(code **)(*DAT_803dcaac + 0x50))(0x1c,0,0);
        break;
      case 6:
        DAT_803ddb80 = DAT_803ddb80 | 0x40004;
        break;
      case 7:
        DAT_803ddb80 = DAT_803ddb80 | 2;
        break;
      case 8:
        iVar7 = *(int *)(iVar9 + 0x40c);
        *(byte *)(iVar7 + 0xb6) = *(byte *)(iVar7 + 0xb6) & 0x7f | 0x80;
        FUN_8000a518(0xee,0);
        break;
      case 9:
        DAT_803ddb80 = DAT_803ddb80 | 0x40;
        break;
      case 10:
        DAT_803ddb80 = DAT_803ddb80 & 0xffffffbf;
        break;
      case 0xc:
        DAT_803ddb80 = DAT_803ddb80 & 0xffffff7f;
        break;
      case 0xd:
        DAT_803ddb80 = DAT_803ddb80 | 0x100;
        break;
      case 0xe:
        DAT_803ddb80 = DAT_803ddb80 & 0xfffffeff;
        break;
      case 0xf:
        DAT_803ddb80 = DAT_803ddb80 | 0x2001;
        break;
      case 0x10:
        DAT_803ddb80 = DAT_803ddb80 | 0x8021;
        break;
      case 0x11:
        *(undefined4 *)(iVar7 + 0xb0) = 10;
        FUN_800200e8(0x123,1);
        FUN_800200e8(0x17,1);
        FUN_8000a518(0x27,0);
        FUN_8000a518(0x36,0);
        FUN_8000a518(0xee,0);
        break;
      case 0x12:
        (**(code **)(*DAT_803dca54 + 0x50))(0x49,4,iVar3,0x3c);
        break;
      case 0x13:
        (**(code **)(*DAT_803dcaac + 0x50))(0x1c,2,1);
        break;
      case 0x14:
        (**(code **)(*DAT_803dcaac + 0x50))(0x1c,2,0);
        break;
      case 0x15:
        FUN_8007d6dc(s__DIMBoss_c__freeing_assets_for_D_80325b44);
        FUN_80043074();
        FUN_8004350c(0,0,1);
        uVar5 = FUN_800481b0(0x1c);
        FUN_800437bc(uVar5,0x3ff);
        uVar5 = FUN_800481b0(0x1b);
        FUN_800437bc(uVar5,0x20000000);
        FUN_80041e3c(0);
        break;
      case 0x16:
        FUN_8007d6dc(s__DIMBoss_c__loading_assets_for_D_80325b6c);
        uVar5 = FUN_800481b0(0x13);
        FUN_80043560(uVar5,0);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x20);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x21);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x23);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x24);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x30);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x2f);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x2b);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x2a);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x26);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x25);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x1a);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0x1b);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0xe);
        uVar5 = FUN_800481b0(0x13);
        FUN_800443cc(uVar5,0xd);
        bVar2 = false;
        while (uVar4 = FUN_800430ac(0), (uVar4 & 0xffefffff) != 0) {
          FUN_80014f40();
          FUN_800202cc();
          if (bVar2) {
            FUN_8004a868();
          }
          FUN_800481d4();
          FUN_80015624();
          if (bVar2) {
            FUN_800234ec(0);
            FUN_80019c24();
            FUN_8004a43c(1,0);
          }
          if (DAT_803dc950 != '\0') {
            bVar2 = true;
          }
        }
        FUN_80043034();
        break;
      case 0x17:
        DAT_803ddb80 = DAT_803ddb80 | 0x80000;
        break;
      case 0x18:
        DAT_803ddb80 = DAT_803ddb80 & 0xfff7ffff;
      }
    }
    if (*(short *)(iVar3 + 0xb4) != -1) {
      iVar7 = (**(code **)(*DAT_803dcab8 + 0x30))(iVar3,iVar9,1);
      if (iVar7 == 0) {
        uVar4 = 1;
        goto LAB_801bd228;
      }
      if (*(int *)(iVar3 + 200) != 0) {
        *(undefined4 *)(*(int *)(iVar3 + 200) + 0x30) = *(undefined4 *)(iVar3 + 0x30);
      }
      if ((*(short *)(iVar9 + 0x3f6) != -1) && (iVar7 = FUN_8001ffb4(), iVar7 != 0)) {
        (**(code **)(*DAT_803dca54 + 0x58))(param_3,(int)*(short *)(iVar8 + 0x2c));
        *(undefined2 *)(iVar9 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)(iVar9 + 0x405);
      if (bVar1 == 1) {
        iVar7 = (**(code **)(*DAT_803dcab8 + 0x34))
                          (iVar3,param_3,iVar9,&DAT_803ad018,&DAT_803ad000,0);
        if (iVar7 != 0) {
          (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e4c70,iVar3,iVar9,1);
        }
      }
      else if ((bVar1 != 0) && (bVar1 < 3)) {
        *(undefined2 *)(param_3 + 0x6e) = 0;
        FUN_801bc7e4(iVar3,param_3,iVar9,iVar9);
        if (*(char *)(iVar9 + 0x405) == '\x01') {
          *(undefined2 *)(iVar9 + 0x270) = 0;
          (**(code **)(*DAT_803dca8c + 8))
                    ((double)FLOAT_803e4c44,(double)FLOAT_803e4c44,iVar3,iVar9,&DAT_803ad018,
                     &DAT_803ad000);
          *(undefined *)(param_3 + 0x56) = 0;
        }
      }
    }
    FUN_801bbb44(iVar3,iVar9);
    if (*(short *)(iVar3 + 0xb4) == -1) {
      *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) | 2;
      uVar4 = 0;
    }
    else {
      uVar4 = -(uint)*(byte *)(iVar9 + 0x405) >> 0x1f;
    }
  }
  else {
    uVar4 = 0;
  }
LAB_801bd228:
  FUN_8028611c(uVar4);
  return;
}

