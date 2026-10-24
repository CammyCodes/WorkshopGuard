using System.Threading.Tasks;

namespace Steamworks.Ugc
{
    // Empty stub with the same names as Facepunch.Steamworks' Workshop uploader.
    public struct Editor
    {
        public static Editor NewCommunityFile => default;
        public Editor WithContent(string folder) => this;
        public Task<int> SubmitAsync() => Task.FromResult(0);
    }
}
