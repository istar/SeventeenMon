module SeventeenMon
  class IP
    attr_reader :ip

    # Initialize IP object
    #
    # == parameters:
    # params::
    #   Might contain address(hostname) and protocol, or just IP
    #
    # == Returns:
    # self
    #
    def initialize(params = {})
      @ip = params[:ip] ||
        Socket.getaddrinfo(params[:address], params[:protocol])[0][3]
    end

    def four_number
      @four_number ||= begin
        fn = ip.split(".").map(&:to_i)
        raise "ip is no valid" if fn.length != 4 || fn.any?{ |d| d < 0 || d > 255}
        fn
      end
    end

    def ip2long
      @ip2long ||= ::IPAddr.new(ip).to_i
    end

    def packed_ip
      @packed_ip ||= [ ip2long ].pack 'N'
    end

    def find
      tmp_offset = four_number[0] * 4
      start = IPDB.instance.index[tmp_offset..(tmp_offset + 3)].unpack("V")[0] * 8 + 1024

      index_offset = nil

      while start < IPDB.instance.max_comp_length
        if IPDB.instance.index[start..(start + 3)] >= packed_ip
          index_offset = "#{IPDB.instance.index[(start + 4)..(start + 6)]}\x0".unpack("V")[0]
          index_length = "#{IPDB.instance.index[(start + 7)]}\x0".unpack("C")[0]
          break
        end
        start += 8
      end

      return "N/A" unless index_offset

      result = IPDB.instance.seek(index_offset, index_length).map do |str|
        #str.encode("UTF-8", "UTF-8")
        force_utf8(str)
      end

      {
        :country => result[0],
        :province => result[1],
        :city => result[2]
      }
    end

    def force_utf8(str)
      return str if str.blank?
      b = str.unpack("C*")

      r = []
      index = 0
      b.each_with_index do | x, i |

        next if i < index
        if x >> 7 == 0b0
          r << x
          index = i

        end
        if x >> 5 == 0b110 && b[i+ 1] && b[i+1] >> 6 == 0b10
          r << x
          r << b[i+1]
          index = i + 1
        end

        if x >> 4 == 0b1110 && b[i+2] && b[i+1] >> 6 == 0b10 && b[i+2] >> 6 == 0b10
          r << x
          r << b[i+1]
          r << b[i+2]
          index = i + 2
        end
        if x >> 3 == 0b11110 && b[i+3] && b[i+1] >> 6 == 0b10 && b[i+2] >> 6 == 0b10 && b[i+3] >> 6 == 0b10
          r << x
          r << b[i+1]
          r << b[i+2]
          r << b[i+3]
          index = i + 2
        end
        if x >> 2 == 0b111110 && b[i+4] && b[i+1] >> 6 == 0b10 && b[i+2] >> 6 == 0b10 &&
          b[i+3] >> 6 == 0b10 &&  b[i+4] >> 6 == 0b10
          r << x
          r << b[i+1]
          r << b[i+2]
          r << b[i+3]
          r << b[i+4]
          index = i + 3
        end
        if x >> 1 == 0b1111110 && b[i+5] && b[i+1] >> 6 == 0b10 && b[i+2] >> 6 == 0b10 &&
          b[i+3] >> 6 == 0b10 &&  b[i+4] >> 6 == 0b10 &&  b[i+5] >> 6 == 0b10
          r << x
          r << b[i+1]
          r << b[i+2]
          r << b[i+3]
          r << b[i+4]
          r << b[i+5]
          index = i + 4
        end
        #break
      end


      r.pack("C*")
    end
  end
end