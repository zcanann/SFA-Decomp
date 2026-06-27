#include "main/engine_shared.h"

void Curve_SampleSegmentPoints(f32* px, f32* py, f32* pz, f32* outX, f32* outY, f32* outZ, int count,
                               void (*evalFn)(f32* ch, f32* buf))
{
    f32 bufX[4];
    f32 bufY[4];
    f32 bufZ[4];
    f32 vx, d1x, d2x, d3x;
    f32 vy, d1y, d2y, d3y;
    f32 vz, d1z, d2z, d3z;
    f32 step;
    int i;

    if (count != gCurveCachedSampleCount)
    {
        step = lbl_803DE674 / count;
        gCurveForwardDiffStep = step;
        gCurveForwardDiffCoeffs[0] = step * step;
        gCurveForwardDiffCoeffs[1] = lbl_803DE660 * gCurveForwardDiffCoeffs[0];
        gCurveForwardDiffCoeffs[2] = step * gCurveForwardDiffCoeffs[0];
        gCurveForwardDiffCoeffs[3] = lbl_803DE680 * gCurveForwardDiffCoeffs[2];
        gCurveCachedSampleCount = count;
    }

    if (px != NULL)
    {
        evalFn(px, bufX);
        vx = bufX[3];
        d1x = gCurveForwardDiffStep * bufX[2] + (gCurveForwardDiffCoeffs[2] * bufX[0] + gCurveForwardDiffCoeffs[0] * bufX[1]);
        d2x = gCurveForwardDiffCoeffs[3] * bufX[0] + gCurveForwardDiffCoeffs[1] * bufX[1];
        d3x = gCurveForwardDiffCoeffs[3] * bufX[0];
    }
    if (py != NULL)
    {
        evalFn(py, bufY);
        vy = bufY[3];
        d1y = gCurveForwardDiffStep * bufY[2] + (gCurveForwardDiffCoeffs[2] * bufY[0] + gCurveForwardDiffCoeffs[0] * bufY[1]);
        d2y = gCurveForwardDiffCoeffs[3] * bufY[0] + gCurveForwardDiffCoeffs[1] * bufY[1];
        d3y = gCurveForwardDiffCoeffs[3] * bufY[0];
    }
    if (pz != NULL)
    {
        evalFn(pz, bufZ);
        vz = bufZ[3];
        d1z = gCurveForwardDiffStep * bufZ[2] + (gCurveForwardDiffCoeffs[2] * bufZ[0] + gCurveForwardDiffCoeffs[0] * bufZ[1]);
        d2z = gCurveForwardDiffCoeffs[3] * bufZ[0] + gCurveForwardDiffCoeffs[1] * bufZ[1];
        d3z = gCurveForwardDiffCoeffs[3] * bufZ[0];
    }

    for (i = 0; i <= count; i++)
    {
        if (px != NULL)
        {
            outX[i] = vx;
            vx += d1x;
            d1x += d2x;
            d2x += d3x;
        }
        if (py != NULL)
        {
            outY[i] = vy;
            vy += d1y;
            d1y += d2y;
            d2y += d3y;
        }
        if (pz != NULL)
        {
            outZ[i] = vz;
            vz += d1z;
            d1z += d2z;
            d2z += d3z;
        }
    }
}

#pragma dont_inline on
void Curve_BuildSegmentLengthTable(Curve* curve, int count)
{
    f32 outX[21];
    f32 outY[21];
    f32 outZ[21];
    int i;
    f32* px = NULL;
    f32* py = NULL;
    f32* pz = NULL;
    f32 dx, dy, dz, sq;
    f32 zero;

    if (curve->px != NULL)
    {
        px = curve->px + curve->idx;
    }
    if (curve->py != NULL)
    {
        py = curve->py + curve->idx;
    }
    if (curve->pz != NULL)
    {
        pz = curve->pz + curve->idx;
    }
    if (curve->coeffFn != 0)
    {
        Curve_SampleSegmentPoints(px, py, pz, outX, outY, outZ, count, curve->coeffFn);
    }

    zero = lbl_803DE658;
    curve->totalLen = zero;
    for (i = 0; i < count; i++)
    {
        dx = px != NULL ? outX[i + 1] - outX[i] : lbl_803DE658;
        dy = py != NULL ? outY[i + 1] - outY[i] : lbl_803DE658;
        dz = pz != NULL ? outZ[i + 1] - outZ[i] : lbl_803DE658;
        sq = dx * dx + dy * dy + dz * dz;
        if (sq > zero)
        {
            curve->segLen[i] = sqrtf(sq);
        }
        else
        {
            curve->segLen[i] = lbl_803DE67C;
        }
        curve->totalLen += curve->segLen[i];
    }
}
#pragma dont_inline reset

typedef f32 (*CurveEvalPtrFirst)(f32 *values, f32 t, f32 *outTangent);

int Curve_AdvanceAlongPath(Curve* curve, f32 dt)
{
    int seg, savedIdx;
    f32* lengths = &curve->totalLen;
    f32 step = dt * timeDelta;
    f32 zero;
    f32 c;
    f32 base, frac, t;

    if (step > lbl_803DE658)
    {
        seg = (int)(gCurveSegmentCount * curve->t);
        if (seg == 20)
        {
            seg--;
        }
        if (curve->dir != 0)
        {
            f32 segLen = lengths[seg + 1];
            curve->segmentDistance = segLen + curve->segmentDistance;
        }
        else if (curve->t >= lbl_803DE674)
        {
            return 1;
        }
        curve->pathDistance += step;
        step += curve->segmentDistance;
        zero = lbl_803DE658;
        while (step > zero)
        {
            step -= lengths[seg + 1];
            if (step > zero && ++seg >= 20)
            {
                savedIdx = curve->idx;
                if (curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite)
                {
                    curve->idx += 3;
                }
                if (++curve->idx > curve->count - 4)
                {
                    if (curve->px != NULL)
                    {
                        curve->sample[0] = ((CurveEvalPtrFirst)curve->eval)(curve->px + savedIdx, lbl_803DE674, &curve->tangent[0]);
                    }
                    if (curve->py != NULL)
                    {
                        curve->sample[1] = ((CurveEvalPtrFirst)curve->eval)(curve->py + savedIdx, lbl_803DE674, &curve->tangent[1]);
                    }
                    if (curve->pz != NULL)
                    {
                        curve->sample[2] = ((CurveEvalPtrFirst)curve->eval)(curve->pz + savedIdx, lbl_803DE674, &curve->tangent[2]);
                    }
                    curve->t = lbl_803DE674;
                    curve->segmentDistance = lbl_803DE658;
                    curve->pathDistance = curve->pathLength;
                    curve->idx = curve->count - 4;
                    return 1;
                }
                Curve_BuildSegmentLengthTable(curve, 20);
                seg = 0;
            }
        }
        step += lengths[seg + 1];
        base = seg / gCurveSegmentCount;
        frac = step / lengths[seg + 1];
        t = frac * ((f32)(seg + 1) / gCurveSegmentCount - base) + base;
        if (curve->px != NULL)
        {
            curve->sample[0] = ((CurveEvalPtrFirst)curve->eval)(curve->px + curve->idx, t, &curve->tangent[0]);
        }
        if (curve->py != NULL)
        {
            curve->sample[1] = ((CurveEvalPtrFirst)curve->eval)(curve->py + curve->idx, t, &curve->tangent[1]);
        }
        if (curve->pz != NULL)
        {
            curve->sample[2] = ((CurveEvalPtrFirst)curve->eval)(curve->pz + curve->idx, t, &curve->tangent[2]);
        }
        curve->t = t;
        curve->segmentDistance = step;
        curve->dir = 0;
    }
    else if (step < lbl_803DE658)
    {
        seg = (int)(gCurveSegmentCount * curve->t);
        if (seg == 20)
        {
            seg--;
        }
        if (curve->dir == 0)
        {
            curve->segmentDistance = lengths[seg + 1] - curve->segmentDistance;
        }
        else if (curve->t <= lbl_803DE658)
        {
            return 1;
        }
        curve->pathDistance += step;
        step += curve->segmentDistance;
        zero = lbl_803DE658;
        while (step < zero)
        {
            step += lengths[seg + 1];
            if (step < zero && --seg < 0)
            {
                savedIdx = curve->idx;
                if (curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite)
                {
                    curve->idx -= 3;
                }
                if (--curve->idx < 0)
                {
                    if (curve->px != NULL)
                    {
                        curve->sample[0] = ((CurveEvalPtrFirst)curve->eval)(curve->px + savedIdx, lbl_803DE658, &curve->tangent[0]);
                    }
                    if (curve->py != NULL)
                    {
                        curve->sample[1] = ((CurveEvalPtrFirst)curve->eval)(curve->py + savedIdx, lbl_803DE658, &curve->tangent[1]);
                    }
                    if (curve->pz != NULL)
                    {
                        curve->sample[2] = ((CurveEvalPtrFirst)curve->eval)(curve->pz + savedIdx, lbl_803DE658, &curve->tangent[2]);
                    }
                    c = lbl_803DE658;
                    curve->t = c;
                    curve->segmentDistance = -lengths[1];
                    curve->pathDistance = c;
                    curve->idx = 0;
                    return 1;
                }
                Curve_BuildSegmentLengthTable(curve, 20);
                seg = 19;
            }
        }
        base = seg / gCurveSegmentCount;
        frac = step / lengths[seg + 1];
        t = frac * ((f32)(seg + 1) / gCurveSegmentCount - base) + base;
        if (curve->px != NULL)
        {
            curve->sample[0] = ((CurveEvalPtrFirst)curve->eval)(curve->px + curve->idx, t, &curve->tangent[0]);
        }
        if (curve->py != NULL)
        {
            curve->sample[1] = ((CurveEvalPtrFirst)curve->eval)(curve->py + curve->idx, t, &curve->tangent[1]);
        }
        if (curve->pz != NULL)
        {
            curve->sample[2] = ((CurveEvalPtrFirst)curve->eval)(curve->pz + curve->idx, t, &curve->tangent[2]);
        }
        curve->t = t;
        curve->segmentDistance = step - lengths[seg + 1];
        curve->dir = 1;
    }
    return 0;
}

void curvesSetupMoveNetworkCurve(Curve* curve)
{
    if (curve->count < 4)
    {
        debugPrintf(sCurvesSetupMoveNetworkCurveTooFewControlPoints);
    }
    if ((curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite) &&
        (curve->count & 3) != 0)
    {
        debugPrintf(sCurvesSetupMoveNetworkCurveBadControlPointCount);
    }

    curve->pathLength = lbl_803DE658;
    curve->idx = 0;
    while (curve->idx < curve->count - 3)
    {
        Curve_BuildSegmentLengthTable(curve, 5);
        curve->pathLength += curve->totalLen;
        if (curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite)
        {
            curve->idx += 4;
        }
        else
        {
            curve->idx += 1;
        }
    }

    if (curve->dir != 0)
    {
        curve->idx = curve->count - 4;
    }
    else
    {
        curve->idx = 0;
    }
    Curve_BuildSegmentLengthTable(curve, 20);
    if (curve->dir != 0)
    {
        curve->pathDistance = curve->pathLength - curve->segmentDistance;
    }
    else
    {
        curve->pathDistance = curve->segmentDistance;
    }
}

void curvesMove(Curve* curve)
{
    if (curve->count < 4)
    {
        debugPrintf(sCurvesMoveTooFewControlPoints);
    }
    if ((curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite) &&
        (curve->count & 3) != 0)
    {
        debugPrintf(sCurvesMoveBadControlPointCount);
    }

    curve->pathLength = lbl_803DE658;
    curve->idx = 0;
    while (curve->idx < curve->count - 3)
    {
        Curve_BuildSegmentLengthTable(curve, 5);
        curve->pathLength += curve->totalLen;
        if (curve->eval == Curve_EvalBezier || curve->eval == Curve_EvalHermite)
        {
            curve->idx += 4;
        }
        else
        {
            curve->idx += 1;
        }
    }

    if (curve->dir != 0)
    {
        curve->idx = curve->count - 4;
    }
    else
    {
        curve->idx = 0;
    }
    Curve_BuildSegmentLengthTable(curve, 20);

    if (curve->dir != 0)
    {
        curve->t = lbl_803DE674;
        curve->segmentDistance = curve->segLen[19];
        curve->pathDistance = curve->pathLength;
    }
    else
    {
        f32 z = lbl_803DE658;
        curve->t = z;
        curve->segmentDistance = z;
        curve->pathDistance = z;
    }

    if (curve->px != NULL)
    {
        curve->sample[0] = curve->eval(curve->t, curve->px, &curve->tangent[0]);
    }
    if (curve->py != NULL)
    {
        curve->sample[1] = curve->eval(curve->t, curve->py, &curve->tangent[1]);
    }
    if (curve->pz != NULL)
    {
        curve->sample[2] = curve->eval(curve->t, curve->pz, &curve->tangent[2]);
    }
}

f32 Curve_EvalLinear(f32 t, f32* values)
{
    return t * (values[1] - values[0]) + values[0];
}

f32 Curve_EvalCatmullRom(f32 t, f32* values, f32* outTangent)
{
    f32 p3 = values[3];
    f32 a = p3 + (lbl_803DE668 * values[2] + (lbl_803DE664 * values[1] + -values[0]));
    f32 b = (lbl_803DE65C * values[2] + (lbl_803DE660 * values[0] + lbl_803DE694 * values[1])) - p3;
    f32 c = -values[0] + values[2];
    f32 d = lbl_803DE660 * values[1];

    if (outTangent != NULL)
    {
        f32 e = lbl_803DE664 * a;
        *outTangent = t * (lbl_803DE660 * b + e * t) + c;
    }
    return lbl_803DE678 * (t * (t * (a * t + b) + c) + d);
}

f32 Curve_EvalBezier(f32 t, f32* values, f32* outTangent)
{
    f32 p0;
    f32 a = values[3];
    f32 b;
    f32 c;

    a += lbl_803DE668 * values[2] + (-(p0 = values[0]) + lbl_803DE664 * values[1]);
    b = lbl_803DE664 * values[2] +
        (lbl_803DE664 * p0 + lbl_803DE66C * values[1]);
    c = lbl_803DE668 * p0 + lbl_803DE664 * values[1];

    if (outTangent != NULL)
    {
        f32 e = lbl_803DE664 * a;
        *outTangent = t * (lbl_803DE660 * b + e * t) + c;
    }
    return t * (t * (a * t + b) + c) + p0;
}

void Curve_BuildHermiteCoeffs(f32* values, f32* coefficients)
{
    f32 k698;

    coefficients[0] = values[3] + (values[2] + (lbl_803DE660 * values[0] + (k698 = lbl_803DE698) * values[1]));
    coefficients[1] = (lbl_803DE668 * values[0] + lbl_803DE664 * values[1] +
            k698 * values[2]) -
        values[3];
    coefficients[2] = values[2];
    coefficients[3] = values[0];
}

f32 Curve_EvalHermite(f32 t, f32* values, f32* outTangent)
{
    f32 p3 = values[3];
    f32 tangent1 = values[2];
    f32 k660 = lbl_803DE660;
    f32 p0 = values[0];
    f32 k698 = lbl_803DE698;
    f32 a = p3 + (tangent1 + (k660 * p0 + k698 * values[1]));
    f32 b = ((lbl_803DE664 * values[1] + lbl_803DE668 * p0) + k698 * tangent1) - p3;

    if (outTangent != NULL)
    {
        f32 e = lbl_803DE664 * a;
        *outTangent = t * (k660 * b + e * t) + tangent1;
    }
    return t * (t * (a * t + b) + tangent1) + p0;
}

void Curve_BuildBSplineCoeffs(f32* values, f32* coefficients)
{
    f32 v3 = values[3];
    f32 k664 = lbl_803DE664;
    f32 k668 = lbl_803DE668;
    f32 scale;

    coefficients[0] = v3 + (k668 * values[2] + (-values[0] + k664 * values[1]));
    coefficients[1] = k664 * values[2] + (k664 * values[0] + lbl_803DE66C * values[1]);
    coefficients[2] = k668 * values[0] + k664 * values[2];
    coefficients[3] = values[2] + (values[0] + lbl_803DE65C * values[1]);

    coefficients[0] *= (scale = lbl_803DE670);
    coefficients[1] *= scale;
    coefficients[2] *= scale;
    coefficients[3] *= scale;
}

f32 Curve_EvalBSpline(f32 t, f32* values, f32* outTangent)
{
    f32 a = values[3];
    f32 b;
    f32 c;
    f32 d;

    a += lbl_803DE668 * values[2] + (-values[0] + lbl_803DE664 * values[1]);
    b = lbl_803DE664 * values[2] +
        (lbl_803DE664 * values[0] + lbl_803DE66C * values[1]);
    c = lbl_803DE668 * values[0] + lbl_803DE664 * values[2];
    d = values[2] + (values[0] + lbl_803DE65C * values[1]);

    if (outTangent != NULL)
    {
        f32 e = lbl_803DE664 * a;
        *outTangent = lbl_803DE670 *
            (t * (lbl_803DE660 * b + e * t) + c);
    }
    return lbl_803DE670 * (t * (t * (a * t + b) + c) + d);
}

void CurveHeap_SiftDown(CurveHeapNode* heap, s32 count, s32 index)
{
    u16 priority = heap[index].priority;
    u16 value = heap[index].value;

    while (index <= count >> 1)
    {
        s32 child = index + index;

        if ((child < count) && (heap[child].priority < heap[child + 1].priority))
        {
            child++;
        }

        if (priority >= heap[child].priority)
        {
            break;
        }

        heap[index].priority = heap[child].priority;
        heap[index].value = heap[child].value;
        index = child;
    }

    heap[index].priority = priority;
    heap[index].value = value;
}
