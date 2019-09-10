#include "path.h"

Path::Path(const ProtoAddress& a)
{
    addr=a;
    nextPath = NULL;
}
Path::Path(const ProtoAddress& a, Path * p)
{
    addr = a;
    nextPath = p;
}

void Path::printPath()
{
    PLOG(PL_ALWAYS, "      %s\n", addr.GetHostString());
    if (nextPath != NULL)
        nextPath->printPath();
}
