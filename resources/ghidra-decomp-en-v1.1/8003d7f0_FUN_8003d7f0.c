// Function: FUN_8003d7f0
// Entry: 8003d7f0
// Size: 648 bytes

void FUN_8003d7f0(int param_1)

{
  int *piVar1;
  double dVar2;
  uint local_58;
  undefined4 local_54;
  uint local_50;
  uint local_4c;
  undefined4 uStack_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  float afStack_38 [12];
  
  local_3c = DAT_803df670;
  piVar1 = FUN_8001f58c(param_1,'\0');
  if (piVar1 != (int *)0x0) {
    FUN_8001dbf0((int)piVar1,4);
    FUN_8001dd54((double)FLOAT_803df684,(double)FLOAT_803df6b4,(double)FLOAT_803df684,piVar1);
    FUN_8001dbb4((int)piVar1,0xff,0xff,0xff,0xff);
    FUN_8001e9b8(0);
    FUN_8001e6cc(2,0,0);
    local_4c = DAT_803dc0d0;
    FUN_8025a2ec(2,&local_4c);
    local_50 = DAT_803dc0c8;
    FUN_8025a454(2,&local_50);
    FUN_8001e568(2,piVar1,param_1);
    FUN_8001e6f8();
    FUN_8001f448((uint)piVar1);
  }
  local_54 = local_3c;
  FUN_8025c510(0,(byte *)&local_54);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c584(0,0xc);
  FUN_8006c63c(&local_40,&local_44,&uStack_48);
  FUN_8004c460(*(int *)(local_40 + ((DAT_803dd8c4 >> 2) + (uint)DAT_803dd8bd * local_44) * 4),0);
  FUN_80247a7c((double)FLOAT_803df6b8,(double)FLOAT_803df6b8,(double)FLOAT_803df69c,afStack_38);
  FUN_8025d8c4(afStack_38,0x40,0);
  FUN_80258674(1,1,4,0x3c,1,0x40);
  FUN_8025be80(0);
  FUN_8025c828(0,1,0,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c224(0,7,4,5,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,3,1,0);
  FUN_8025ca04(1);
  FUN_8025be54(0);
  FUN_80258944(2);
  FUN_80259288(2);
  local_58 = DAT_803dc0c8;
  dVar2 = (double)FLOAT_803df684;
  FUN_8025ca38(dVar2,dVar2,dVar2,dVar2,0,(uint3 *)&local_58);
  FUN_8007048c(1,3,0);
  FUN_80070434(1);
  FUN_8025cce8(1,4,5,5);
  return;
}

