// Function: FUN_8003c360
// Entry: 8003c360
// Size: 2484 bytes

/* WARNING: Removing unreachable block (ram,0x8003ccec) */
/* WARNING: Removing unreachable block (ram,0x8003c370) */

undefined4 FUN_8003c360(int param_1,int *param_2,int param_3)

{
  undefined uVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  uint *puVar5;
  uint uVar6;
  int *piVar7;
  double dVar8;
  uint local_190;
  undefined4 local_18c;
  uint local_188;
  uint local_184;
  undefined4 local_180;
  undefined4 uStack_17c;
  int local_178;
  int local_174;
  undefined4 local_170;
  float local_16c;
  float local_168;
  int local_164;
  uint local_160;
  int local_15c;
  undefined4 local_158;
  float local_154;
  float local_150;
  undefined4 local_14c;
  undefined4 local_148;
  undefined4 local_144;
  float local_140;
  float local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  float local_12c;
  undefined4 local_128;
  float afStack_124 [12];
  float local_f4 [5];
  float local_e0;
  float afStack_c4 [12];
  float afStack_94 [12];
  float afStack_64 [13];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  local_158 = DAT_803df67c;
  local_13c = DAT_802c22c0;
  local_138 = DAT_802c22c4;
  local_134 = DAT_802c22c8;
  local_130 = DAT_802c22cc;
  local_12c = (float)DAT_802c22d0;
  local_128 = DAT_802c22d4;
  local_154 = DAT_802c22d8;
  local_150 = (float)DAT_802c22dc;
  local_14c = DAT_802c22e0;
  local_148 = DAT_802c22e4;
  local_144 = DAT_802c22e8;
  local_140 = (float)DAT_802c22ec;
  iVar3 = FUN_800284e8(*param_2,param_3);
  if ((*(uint *)(iVar3 + 0x3c) & 0x200) == 0) {
    if ((DAT_803dd8c4 & 3) == 0) {
      DAT_803dd8be = 1;
      FUN_8003d7f0(param_1);
      uVar4 = 1;
    }
    else {
      DAT_803dd8be = 0;
      uVar4 = 0;
    }
  }
  else {
    DAT_803dd8be = 1;
    FUN_8006c65c(&local_15c,&local_160);
    uStack_2c = DAT_803dd8c4 ^ 0x80000000;
    local_30 = 0x43300000;
    uStack_24 = local_160 ^ 0x80000000;
    local_28 = 0x43300000;
    fVar2 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df6c0) /
            (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df6c0);
    dVar8 = (double)(fVar2 * fVar2 * FLOAT_803df6a8);
    puVar5 = (uint *)FUN_8004c3cc(iVar3,0);
    uVar6 = FUN_8005383c(*puVar5);
    FUN_8004c460(uVar6,0);
    FUN_80258674(2,1,4,0x3c,0,0x7d);
    FUN_8025be80(0);
    FUN_8025c828(0,2,0,0xff);
    FUN_8025c1a4(0,0xf,0xf,0xf,8);
    FUN_8025c224(0,7,7,7,7);
    FUN_8025c65c(0,0,0);
    FUN_8025c2a8(0,0,0,0,0,0);
    FUN_8025c368(0,0,0,0,1,0);
    uVar1 = *(undefined *)(param_1 + 0xf1);
    local_158 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_158)));
    local_180 = local_158;
    FUN_8025c510(0,(byte *)&local_180);
    FUN_8025c5f0(1,0x1c);
    FUN_8025c584(1,0xc);
    FUN_80247a7c((double)FLOAT_803df6ac,(double)FLOAT_803df6ac,(double)FLOAT_803df684,afStack_94);
    FUN_80247a48((double)FLOAT_803df6a8,(double)FLOAT_803df6a8,(double)FLOAT_803df69c,afStack_c4);
    FUN_80247618(afStack_c4,afStack_94,afStack_94);
    FUN_8025d8c4(afStack_94,0x43,0);
    FUN_80258674(0,1,1,0x1e,0,0x43);
    piVar7 = (int *)FUN_8002867c((int)param_2,param_3);
    FUN_8004c460(*piVar7,1);
    FUN_8025be80(1);
    FUN_8025c828(1,0,1,4);
    FUN_8025c65c(1,0,0);
    FUN_8025c1a4(1,0xf,8,0xe,10);
    FUN_8025c224(1,7,7,7,7);
    FUN_8025c2a8(1,0,0,0,1,2);
    FUN_8025c368(1,0,0,0,1,0);
    FUN_8006c760(&local_164);
    FUN_8004c460(local_164,4);
    FUN_8006cc38(&local_168,&local_16c);
    FUN_80247a48((double)(FLOAT_803df6a8 * local_168),(double)(FLOAT_803df6a8 * local_16c),
                 (double)FLOAT_803df684,local_f4);
    local_f4[0] = FLOAT_803df69c;
    local_e0 = FLOAT_803df69c;
    FUN_8025d8c4(local_f4,0x46,0);
    FUN_80258674(1,1,4,0x3c,0,0x46);
    FUN_8025bd1c(0,1,4);
    FUN_8025bb48(0,0,0);
    local_13c = (float)dVar8;
    local_12c = (float)dVar8;
    FUN_8025b9e8(1,&local_13c,(char)DAT_803dc0f8);
    FUN_8025b94c(2,0,0,7,1,6,6,0,0,0);
    FUN_8025c828(2,0xff,0xff,0xff);
    FUN_8025c65c(2,0,0);
    FUN_8025c1a4(2,0xf,0,4,0xf);
    FUN_8025c224(2,7,7,7,7);
    FUN_8025c2a8(2,0,0,0,1,0);
    FUN_8025c368(2,0,0,0,1,0);
    uVar6 = FUN_8005383c(*(uint *)(iVar3 + 0x38));
    FUN_8004c460(uVar6,2);
    FUN_80258674(3,1,4,0x3c,0,0x7d);
    FUN_8025bd1c(1,3,2);
    FUN_8025bb48(1,0,0);
    local_150 = (float)dVar8;
    local_140 = (float)dVar8;
    FUN_8025b9e8(2,&local_154,(char)DAT_803dc0fc);
    FUN_8025b94c(3,1,0,7,2,0,0,1,0,1);
    FUN_8004c460(*(int *)(local_15c + DAT_803dd8c4 * 4),3);
    FUN_80247a7c((double)FLOAT_803df6b0,(double)FLOAT_803df6b0,(double)FLOAT_803df69c,afStack_64);
    FUN_8025d8c4(afStack_64,0x40,0);
    FUN_80258674(4,1,4,0x3c,1,0x40);
    FUN_8025c584(3,4);
    FUN_8025c828(3,4,3,8);
    FUN_8025c1a4(3,8,0xe,0,0);
    FUN_8025c224(3,7,4,5,7);
    FUN_8025c65c(3,0,0);
    FUN_8025c2a8(3,1,1,0,1,0);
    FUN_8025c368(3,0,0,0,1,0);
    if ((int)DAT_803dd8c4 < 0xc) {
      FUN_8025ca04(4);
      FUN_8025be54(2);
      FUN_80258944(5);
    }
    else {
      local_170 = DAT_803df680;
      piVar7 = FUN_8001f58c(param_1,'\0');
      if (piVar7 != (int *)0x0) {
        FUN_8001dbf0((int)piVar7,4);
        FUN_8001dd54((double)FLOAT_803df684,(double)FLOAT_803df6b4,(double)FLOAT_803df684,piVar7);
        FUN_8001dbb4((int)piVar7,0xff,0xff,0xff,0xff);
        FUN_8001e9b8(0);
        FUN_8001e6cc(2,0,0);
        local_184 = DAT_803dc0d0;
        FUN_8025a2ec(2,&local_184);
        local_188 = DAT_803dc0c8;
        FUN_8025a454(2,&local_188);
        FUN_8001e568(2,piVar7,param_1);
        FUN_8001e6f8();
        FUN_8001f448((uint)piVar7);
      }
      local_18c = local_170;
      FUN_8025c510(0,(byte *)&local_18c);
      FUN_8025c5f0(5,0x1c);
      FUN_8025c584(5,0xc);
      FUN_8006c63c(&local_174,&local_178,&uStack_17c);
      FUN_8004c460(*(int *)(local_174 + (DAT_803dd8c4 + (uint)DAT_803dd8bd * local_178 + -0xc) * 4),
                   5);
      FUN_80247a7c((double)FLOAT_803df6b8,(double)FLOAT_803df6b8,(double)FLOAT_803df69c,afStack_124)
      ;
      FUN_8025d8c4(afStack_124,0x49,0);
      FUN_80258674(5,1,4,0x3c,1,0x49);
      FUN_8025be80(4);
      FUN_8025c828(4,5,5,4);
      FUN_8025c1a4(4,0xf,0xf,0xf,0);
      FUN_8025c224(4,7,4,5,7);
      FUN_8025c65c(4,0,0);
      FUN_8025c2a8(4,0,0,0,1,0);
      FUN_8025c368(4,0,0,0,1,2);
      FUN_8025be80(5);
      FUN_8025c828(5,0xff,0xff,0xff);
      FUN_8025c1a4(5,0,0xe,5,0xf);
      FUN_8025c224(5,0,2,2,7);
      FUN_8025c65c(5,0,0);
      FUN_8025c2a8(5,0,0,0,1,0);
      FUN_8025c368(5,0,0,0,1,0);
      FUN_8025ca04(6);
      FUN_8025be54(2);
      FUN_80258944(6);
    }
    FUN_80259288(2);
    local_190 = DAT_803dc0c8;
    dVar8 = (double)FLOAT_803df684;
    FUN_8025ca38(dVar8,dVar8,dVar8,dVar8,0,(uint3 *)&local_190);
    FUN_8007048c(1,3,0);
    FUN_80070434(1);
    FUN_8025cce8(1,4,5,5);
    uVar4 = 1;
  }
  return uVar4;
}

