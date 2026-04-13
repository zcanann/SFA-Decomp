// Function: FUN_8007668c
// Entry: 8007668c
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x80076978) */
/* WARNING: Removing unreachable block (ram,0x80076970) */
/* WARNING: Removing unreachable block (ram,0x800766a4) */
/* WARNING: Removing unreachable block (ram,0x8007669c) */

void FUN_8007668c(double param_1,double param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  double dVar2;
  double dVar3;
  
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_8025cdec(0);
  FUN_8025c828(0,0xff,0xff,4);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xc);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025a608(0,0,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a5bc(1);
  FUN_8025be54(0);
  FUN_80258944(0);
  FUN_8025ca04(1);
  FUN_80259288(0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 7)) || (DAT_803ddc92 != '\x01')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,7,1);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 7;
    DAT_803ddc92 = '\x01';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\0') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(0);
    DAT_803ddc91 = '\0';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025cce8(0,1,0,5);
  FUN_8025d888(0x3c);
  dVar2 = (double)(float)((double)FLOAT_803dfbac * param_1);
  dVar3 = (double)(float)((double)FLOAT_803dfbac * param_2);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_2_ = (short)(int)dVar2;
  DAT_cc008000._0_2_ = (short)(int)dVar3;
  DAT_cc008000._0_2_ = 0xfe74;
  uVar1 = (undefined2)
          (int)(dVar2 + (double)(float)((double)CONCAT44(0x43300000,param_3 << 2) - DOUBLE_803dfb80)
               );
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000._0_2_ = (short)(int)dVar3;
  DAT_cc008000._0_2_ = 0xfe74;
  DAT_cc008000._0_2_ = uVar1;
  uVar1 = (undefined2)
          (int)(dVar3 + (double)(float)((double)CONCAT44(0x43300000,param_4 << 2) - DOUBLE_803dfb80)
               );
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000._0_2_ = 0xfe74;
  DAT_cc008000._0_2_ = (short)(int)dVar2;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000._0_2_ = 0xfe74;
  FUN_8000fb20();
  FUN_8025cdec(1);
  return;
}

