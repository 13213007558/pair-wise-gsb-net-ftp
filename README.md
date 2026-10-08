# Net::FTP

This class implements the File Transfer Protocol.  If you have used a
command-line FTP program, and are familiar with the commands, you will be
able to use this class easily.  Some extra features are included to take
advantage of Ruby's style and strengths.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'net-ftp'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install net-ftp

## Usage

### Example 1

```ruby
ftp = Net::FTP.new('example.com')
ftp.login
files = ftp.chdir('pub/lang/ruby/contrib')
files = ftp.list('n*')
ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
ftp.close
```

### Example 2

```ruby
Net::FTP.open('example.com') do |ftp|
  ftp.login
  files = ftp.chdir('pub/lang/ruby/contrib')
  files = ftp.list('n*')
  ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
end
```

## Path encoding

The encoding of file and directory names on the FTP control connection is
configured per connection with the `path_encoding` option. File contents are
never converted.

```ruby
# legacy server speaking Shift_JIS
ftp = Net::FTP.new('example.com', path_encoding: 'Shift_JIS')

# negotiate RFC 2640 UTF-8 with FEAT / OPTS UTF8 ON after login
ftp = Net::FTP.new('example.com', path_encoding: :utf8)
```

With `nil` (the default), names are passed through verbatim as ASCII-8BIT.
With a legacy encoding, names sent to the server are encoded and names from
listings and replies (NLST, LIST, MLST, MLSD, PWD, ...) are decoded to UTF-8;
bytes that are not valid in the legacy encoding are preserved losslessly, so
names returned by a listing can always be used to access the same entries
again. With `:utf8`, the connection stays in raw-byte mode if the server does
not advertise `UTF8` in `FEAT` or rejects `OPTS UTF8 ON`, and login raises.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/net-ftp.
