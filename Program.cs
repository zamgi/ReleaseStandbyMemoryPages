using System.Threading;

namespace System.Win32
{
    /// <summary>
    /// 
    /// </summary>
    internal static class Program
	{
        private static void Main( string[] args )
        {
            try
            {
                ReleaseStandbyMemoryPages.Exec();

                Console.WriteLine( "ReleaseStandbyMemoryPages::cmd::MemoryPurgeStandbyList => Success." );
                Thread.Sleep( 1_000 );
            }
            catch ( Exception ex )
            {
                var fc = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine( ex.GetBaseException().Message );
                Console.ForegroundColor = fc;

                Console.ReadLine();
            }
        }
    }
}
