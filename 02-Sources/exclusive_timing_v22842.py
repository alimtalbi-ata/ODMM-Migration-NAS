"""Exclusive timing from interval evidence; no overlapping-stage double counting."""

def exclusive_timings(events):
    intervals=[]
    for event in events:
        if not all(k in event for k in ('stage','start_ns','end_ns')):
            raise ValueError('interval evidence required; legacy elapsed-only events are not additive')
        start,end=int(event['start_ns']),int(event['end_ns'])
        if start>end:raise ValueError('negative interval')
        intervals.append((event['stage'],start,end))
    output={}
    for i,(name,start,end) in enumerate(intervals):
        children=[]
        for j,(_,a,b) in enumerate(intervals):
            if i!=j and start<=a<=b<=end and (a>start or b<end or j>i):
                children.append((a,b))
        children.sort()
        covered=0;left=None;right=None
        for a,b in children:
            if left is None:left,right=a,b
            elif a<=right:right=max(right,b)
            else:covered+=right-left;left,right=a,b
        if left is not None:covered+=right-left
        output[name]=output.get(name,0)+max(0,end-start-covered)
    return output
