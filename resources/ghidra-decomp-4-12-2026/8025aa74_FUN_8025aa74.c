// Function: FUN_8025aa74
// Entry: 8025aa74
// Size: 628 bytes

void FUN_8025aa74(uint *param_1,uint param_2,uint param_3,uint param_4,uint param_5,uint param_6,
                 int param_7,char param_8)

{
  int iVar1;
  int iVar2;
  
  FUN_800033a8((int)param_1,0,0x20);
  *param_1 = *param_1 & 0xfffffffc | param_6;
  *param_1 = *param_1 & 0xfffffff3 | param_7 << 2;
  *param_1 = *param_1 & 0xffffffef | 0x10;
  if (param_8 == '\0') {
    *param_1 = *param_1 & 0xffffff1f | 0x80;
  }
  else {
    *(byte *)((int)param_1 + 0x1f) = *(byte *)((int)param_1 + 0x1f) | 1;
    if (param_5 - 8 < 3) {
      *param_1 = *param_1 & 0xffffff1f | 0xa0;
    }
    else {
      *param_1 = *param_1 & 0xffffff1f | 0xc0;
    }
    if ((param_4 & 0xffff) < (param_3 & 0xffff)) {
      iVar1 = countLeadingZeros(param_3 & 0xffff);
    }
    else {
      iVar1 = countLeadingZeros(param_4 & 0xffff);
    }
    param_1[1] = ((int)(FLOAT_803e8368 *
                       (float)((double)CONCAT44(0x43300000,0x1f - iVar1) - DOUBLE_803e8370)) & 0xffU
                 ) << 8 | param_1[1] & 0xffff00ff;
  }
  param_1[5] = param_5;
  param_1[2] = param_1[2] & 0xfffffc00 | (param_3 & 0xffff) - 1;
  param_1[2] = param_1[2] & 0xfff003ff | ((param_4 & 0xffff) - 1) * 0x400;
  param_1[2] = (param_5 & 0xf) << 0x14 | param_1[2] & 0xff0fffff;
  param_1[3] = param_1[3] & 0xffe00000 | param_2 >> 5 & 0x1ffffff;
  switch(param_5 & 0xf) {
  case 0:
  case 8:
    *(undefined *)((int)param_1 + 0x1e) = 1;
    iVar1 = 3;
    iVar2 = 3;
    break;
  case 1:
  case 2:
  case 9:
    *(undefined *)((int)param_1 + 0x1e) = 2;
    iVar1 = 3;
    iVar2 = 2;
    break;
  case 3:
  case 4:
  case 5:
  case 10:
    *(undefined *)((int)param_1 + 0x1e) = 2;
    iVar1 = 2;
    iVar2 = 2;
    break;
  case 6:
    *(undefined *)((int)param_1 + 0x1e) = 3;
    iVar1 = 2;
    iVar2 = 2;
    break;
  default:
    *(undefined *)((int)param_1 + 0x1e) = 2;
    iVar1 = 2;
    iVar2 = 2;
    break;
  case 0xe:
    *(undefined *)((int)param_1 + 0x1e) = 0;
    iVar1 = 3;
    iVar2 = 3;
  }
  *(ushort *)(param_1 + 7) =
       (short)((int)((param_3 & 0xffff) + (1 << iVar1) + -1) >> iVar1) *
       (short)((int)((param_4 & 0xffff) + (1 << iVar2) + -1) >> iVar2) & 0x7fff;
  *(byte *)((int)param_1 + 0x1f) = *(byte *)((int)param_1 + 0x1f) | 2;
  return;
}

