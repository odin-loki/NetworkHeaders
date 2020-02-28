/**
 * A simple byte serialization interface
 */
public interface ICopyable
{

    /**
     * @param dest the byte array to copy to
     * @param offset the position to start at
     * @return the number of bytes written
     */
    int CopyTo(byte[] dest, int offset);
    /**
     * @return How many bytes would this take to represent.
     *
     * Prefer not to call this method.  It may require as much work
     * as CopyTo internally, so if you can write first and then
     * get the length written returned from CopyTo, it will be faster
     * to do so.
     */
    int Length { get; }
}

/**
 * Join (without yet copying) a set of ICopyable objects
 */
public class CopyList : ICopyable
{

    protected ICopyable[] _cs;

    /**
     * How many Copyable objects are in this list
     */
    public int Count
    {
        get { return _cs.Length; }
    }

    /**
     * Get out individual elements from the list
     */
    public ICopyable this[int idx]
    {
        get { return _cs[idx]; }
    }

    /**
     * @param cs is an IEnumerable of ICopyable objects
     */
    public CopyList(params ICopyable[] cs)
    {
        _cs = cs;
    }

    /**
     * Copy in order the entire set
     */
    public int CopyTo(byte[] dest, int offset)
    {
        int total = 0;
        for (int i = 0; i < _cs.Length; i++)
        {
            ICopyable c = _cs[i];
            total += c.CopyTo(dest, offset + total);
        }
        return total;
    }
    public int Length
    {
        get
        {
            int total_length = 0;
            for (int i = 0; i < _cs.Length; i++)
            {
                ICopyable c = _cs[i];
                total_length += c.Length;
            }
            return total_length;
        }
    }
}
