#if defined(__INTELLISENSE__)
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <sstream>
#include <variant>
#include <iomanip>
#else
import <Windows.h>;
import <string>;
import <unordered_map>;
import <sstream>;
import <variant>;
import <iomanip>;
#endif
#include <winhttp.h>;
#include "magic.hpp"//github.com/anohobby/cpp_magic
#pragma comment(lib, "winhttp.lib")
export module http;

namespace http {
	export class URL {
	private:
		std::wstring host_name, url_path;
		unsigned short port;
		bool is_https;
	public:
		URL(std::wstring&& url) {
			URL_COMPONENTS urlComponents = { 0 };
			urlComponents.dwStructSize = sizeof(URL_COMPONENTS);
			constexpr auto GET_SIZE = -1;
			urlComponents.dwSchemeLength = urlComponents.dwHostNameLength = urlComponents.dwUrlPathLength = urlComponents.dwExtraInfoLength = GET_SIZE;
			WinHttpCrackUrl(url.c_str(), url.size(), 0, &urlComponents);
			host_name.resize(urlComponents.dwHostNameLength);
			url_path.resize(urlComponents.dwUrlPathLength);
			urlComponents = { 0 };
			urlComponents.dwStructSize = sizeof(URL_COMPONENTS);
			urlComponents.lpszHostName = host_name.data();
			urlComponents.dwHostNameLength = host_name.size() + 1;
			urlComponents.lpszUrlPath = url_path.data();
			urlComponents.dwUrlPathLength = url_path.size() + 1;
			WinHttpCrackUrl(url.c_str(), url.size(), 0, &urlComponents);
			port = urlComponents.nPort;
			is_https = (INTERNET_SCHEME_HTTPS == urlComponents.nScheme);
		}
		const auto& get_host_name()const noexcept {
			return host_name;
		}
		const auto& get_url_path()const noexcept {
			return url_path;
		}
		const auto& get_port()const noexcept {
			return port;
		}
		const auto& get_is_https()const noexcept {
			return is_https;
		}
	};
	template <
		magic::String Separator,
		class T,
		class Stream = std::basic_stringstream<typename decltype(Separator)::value_type >
	>
	class Container {
	private:
		T data;
	protected:
		using string_type = std::basic_string<typename decltype(Separator)::value_type>;
		using data_type = T;
		using construct_type = std::initializer_list<typename T::value_type>;
	public:
		Container(construct_type data):data(data){}
		virtual string_type to_string()const {
			Stream result;
			for (bool need_line_feed = false; const std::variant<typename T::value_type> &i: data) {//pairが入ってる
				if (need_line_feed) {
					result << Separator.buffer;
				}
				std::visit([&result](auto v){
					result << v;
				}, i);
				need_line_feed = true;
			}
			return std::move(result.str());
		}
	};
	template <magic::String Separator,class Stream>
	class KeyValueStream {
	private:
		Stream base;
	public:
		KeyValueStream& operator<<(const auto& def) {
			base << def;
			return *this;
		}
		template <class T,class U>
		KeyValueStream& operator<<(const std::pair<T,U>& def) {
			base << def.first<<Separator.buffer<<def.second;
			return *this;
		}
		std::basic_string<typename decltype(Separator)::value_type > str()const {
			return std::move(base.str());
		}
	};
	template <
		magic::String Separator,
		magic::String LineFeed,
		class Value_Type= std::basic_string<typename decltype(Separator)::value_type >
	>
	using KeyValue = Container<
		LineFeed,
		std::unordered_multimap<
		std::basic_string<typename decltype(Separator)::value_type >,
		Value_Type
		>,
		KeyValueStream<Separator, std::basic_stringstream<typename decltype(Separator)::value_type > >
	>;
	export using Form_Url_Encoded =KeyValue<"=","&">;
	export using Header = KeyValue<L":",L"\r\n">;
	namespace json {
	template <class T>
	class Visit_Stream {
	private:
		T ss;
	public:
		template <class... T>
		Visit_Stream& operator<<(const std::variant<T...>& variant) {
			std::visit([&](auto v) {
				ss << v;
				}, variant);
			return *this;
		}
		
		Visit_Stream& operator<<(const auto& value) {
			ss << value;
			return *this;
		}
		std::string str()const {
			return ss.str();
		}
	};
	template <auto front, auto back, class T>
	class Scope :public T {
	private:
	public:
		using T::T;
		std::string to_string()const override {
			std::stringstream ss;
			ss << front << T::to_string() << back;
			return std::move(ss.str());
		}
	};
	class Array_Container;
	class Object_Container;
	template <class T>
	class Visit_Container_Stream {
	private:
		T ss;
	public:
		//template <class T> requires requires(T s) { s.to_string(); }
		template <auto front, auto back, class T>
		Visit_Container_Stream& operator<<(const Scope<front,back,T>& value) {
			ss << value.to_string().c_str();//std::stringだとエスケープされてしまう
			return *this;
		}
		Visit_Container_Stream& operator<<(const auto& value) {
			ss << value;
			return *this;
		}
		std::string str()const {
			return ss.str();
		}
	};
	class Json_Stream {
	private:
		std::stringstream base;
	public:
		Json_Stream& operator<<(const auto& value) {
			base << value;
			return *this;
		}
		std::string str()const {
			return base.str();
		}

		Json_Stream& operator<<(const std::nullptr_t& null) {
			base << "null";//magic
			return *this;
		}
		Json_Stream& operator<<(const std::string& str) {
			base << "\"";
			for (const auto& c : str) {
				switch (c) {
				case '\"':
					base << "\\\"";
					break;
				case '\\':
					base << "\\\\";
					break;
				case '\b':
					base << "\\b";
					break;
				case'\f':
					base << "\\f";
					break;
				case '\n':
					base << "\\n";
					break;
				case '\r':
					base << "\\r";
					break;
				case '\t':
					base << "\\t";
					break;
				default:
					base << c;
				}
			}
			base << "\"";
			return *this;
		}

	};

		export using Array = Scope<'[', ']', Array_Container>;
		export using Object = Scope<'{', '}', Object_Container>;
		using json_value_types = std::variant<std::string, Object, Array, int, bool, std::nullptr_t, double>;
		class Array_Container :public Container<",", std::vector<json_value_types>, Visit_Stream<Visit_Container_Stream<Json_Stream> > > {
		private:
		public:
			Array_Container(Container::construct_type data) :Container(data) {

			}
		};
		class Object_Container :public Container<",", std::unordered_map<std::string, json_value_types >, KeyValueStream<":", Visit_Stream<Visit_Container_Stream<Json_Stream>> > > {
		private:
		public:
			Object_Container(Container::construct_type data) :Container(data) {

			}
		};
	};
	export class Client {
	public:
		enum class methods {
			GET,
			POST
		};
	private:
		class Handle {
		private:
			const HINTERNET handle;
		public:
			Handle(HINTERNET&& handle) :handle(handle) {

			}
			~Handle() {
				WinHttpCloseHandle(handle);
			}
			const auto& get()const noexcept {
				return handle;
			}
		};
		const URL url;
		const Handle session, connect;
		template <methods method>
		class Request {
		private:
			const Handle request;
		public:
			Request(const Handle& connect, const URL& url, std::wstring&& header, std::string&& body) :
				request(
					WinHttpOpenRequest(
						connect.get(),
						[] {

							constexpr auto method_name = magic::get_enum_value_name<method>();
							return magic::String<wchar_t, method_name.size()>(method_name.data()).buffer;
						}(),
							url.get_url_path().c_str(),
							nullptr,
							WINHTTP_NO_REFERER,
							WINHTTP_DEFAULT_ACCEPT_TYPES,
							url.get_is_https() ? WINHTTP_FLAG_SECURE : 0
							))
			{
				WinHttpSendRequest(
					request.get(),
					header.data(),
					-1,
					body.data(),
					body.size(),
					body.size(),
					0
				);
				WinHttpReceiveResponse(request.get(), nullptr);
			}
			auto query_header() {
				DWORD size;
				WinHttpQueryHeaders(request.get(),
					WINHTTP_QUERY_RAW_HEADERS_CRLF,
					WINHTTP_HEADER_NAME_BY_INDEX,
					WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
				std::wstring header;
				header.resize(size);
				WinHttpQueryHeaders(request.get(),
					WINHTTP_QUERY_RAW_HEADERS_CRLF,
					WINHTTP_HEADER_NAME_BY_INDEX,
					header.data(), &size, WINHTTP_NO_HEADER_INDEX);
				return std::move(header);
			}
			unsigned short query_status_code() {
				DWORD status, status_size = sizeof(status);
				WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &status_size, nullptr);
				return status;
			}
			auto read_content() {
				std::string content;
				std::size_t total_size = 0;
				while (1) {
					DWORD size;
					WinHttpQueryDataAvailable(request.get(), &size);
					if (!size)break;
					content.resize(total_size + size);
					WinHttpReadData(request.get(), &content[total_size], size, nullptr);
					total_size += size;
				}
				return std::move(content);
			}
		};
	public:
		Client(std::wstring&& url, std::wstring&& user_agent = L"") :
			url(std::move(url)),
			session(WinHttpOpen(user_agent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)),
			connect(WinHttpConnect(session.get(), this->url.get_host_name().c_str(), this->url.get_port(), 0))
		{

		}
		template <methods method>
		auto request(Header&& header = {}, std::string&& body = {}) {
			return Request<method>(connect, url, std::move(header.to_string()), std::move(body));
		}
	};

};