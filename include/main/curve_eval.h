#ifndef MAIN_CURVE_EVAL_H_
#define MAIN_CURVE_EVAL_H_

#include "global.h"

typedef f32 (*CurveEvalFn)(f32 t, f32* values, f32* outTangent);
typedef void (*CurveCoeffFn)(f32* values, f32* coeffs);
typedef f32 (*CurveEvalValuesFirstFn)(f32* values, f32 t, f32* outTangent);

f32 Curve_EvalLinear(f32* values, f32 t, f32* unused);
f32 Curve_EvalCatmullRom(void* valuesArg, f32 t, f32* outTangent);
f32 Curve_EvalBezier(f32 t, f32* values, f32* outTangent);
f32 Curve_EvalHermite(f32 t, f32* values, f32* outTangent);
void Curve_BuildHermiteCoeffs(f32* values, f32* coefficients);
f32 Curve_EvalBSpline(f32* values, f32 t, f32* outTangent);
void Curve_BuildBSplineCoeffs(f32* values, f32* coefficients);

/* Some Hermite callers retain the values-first callback ABI. */
#define Curve_EvalHermiteValuesFirst(values, t, out) \
    (((CurveEvalValuesFirstFn)Curve_EvalHermite)((f32*)(values), (t), (f32*)(out)))

#endif /* MAIN_CURVE_EVAL_H_ */
