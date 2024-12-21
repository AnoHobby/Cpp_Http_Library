#if defined(__INTELLISENSE__)
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <sstream>
#include <variant>
#include <iomanip>
#include <fstream>
#include <random>
#include <filesystem>
#include <algorithm>
#include <memory>
#else
import <Windows.h>;
import <string>;
import <unordered_map>;
import <sstream>;
import <variant>;
import <iomanip>;
import <fstream>;
import <random>;
import <filesystem>;
import <algorithm>;
import <memory>;
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
		URL(std::wstring&& url,std::wstring&& query_parameter=L"") {
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
			if (query_parameter.empty())return;
			url_path.append(L"?");
			url_path.append(query_parameter);
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
	protected:
		T data;
		using string_type = std::basic_string<typename decltype(Separator)::value_type>;
		using data_type = T;
	public:
		using construct_type = std::initializer_list<typename T::value_type>;
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
	export using Query_Parameter = KeyValue<L"=", L"&">;
	export using Cookie = KeyValue<L"=", L";">;
	using Header_Type = KeyValue<L":",L"\r\n">;
	export class Header:public Header_Type{
	private:
	public:
		Header(Header_Type::construct_type data):Container(data){}
		auto emplace(auto&&... args) {
			data.emplace(std::forward<decltype(args)>(args)...);
		}
	};
	export class Data_Type {
	private:
		Header header;
	public:
		virtual std::string to_string_body() = 0;
		virtual std::wstring to_string_header() {
			return std::move(header.to_string());
		}
		Data_Type(decltype(header) && header = {}) :header(header) {};
		auto emplace(auto&&... args) {
			header.emplace(std::forward<decltype(args)>(args)...);
		}
	};
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
	export class Json :public Data_Type {
	private:
		json::Object json;
		auto init() {
			emplace(L"Content-Type", L"application/json");
		}
	public:
		Json(Header&& header = {},json::Object::construct_type data = {}) :Data_Type(std::move(header)), json(data) {
			init();
		}
		Json(json::Object::construct_type data) : json(data) {
			init();
		}
		std::string to_string_body()override {
			return std::move(json.to_string());
		}
	};
	export enum class methods {
		GET,
		POST
	};
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
	template <methods method>
	class Request {
	private:
		const Handle connect,request;
	public:
		Request(const Handle& session, const URL& url, std::wstring&& header, std::string&& body) :
			connect(WinHttpConnect(session.get(),url.get_host_name().c_str(), url.get_port(), 0)),
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
		auto query_cookies() {
			std::vector<std::wstring> cookies;
			for (DWORD index=0;;++index) {
				DWORD size;
				WinHttpQueryHeaders(request.get(),
					WINHTTP_QUERY_SET_COOKIE,
					WINHTTP_HEADER_NAME_BY_INDEX,
					WINHTTP_NO_OUTPUT_BUFFER, &size, &index);
				if (GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND)break;
				std::wstring header;
				header.resize(size);
				WinHttpQueryHeaders(request.get(),
					WINHTTP_QUERY_SET_COOKIE,
					WINHTTP_HEADER_NAME_BY_INDEX,
					header.data(), &size, &index);
				cookies.push_back(std::move(header));
			}
			return std::move(cookies);
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
	export class Multipart:public Data_Type{
	private:
		static constexpr auto BOUNDARY_SIZE = 60;
		std::string boundary;
		std::stringstream body;
		auto generate_boundary() {
			static std::default_random_engine engine((std::random_device())());
			static std::uniform_int_distribution<> getRandom('0', 'z');
			boundary.resize(BOUNDARY_SIZE);//todo:const variable
			for (auto& c : boundary) {
				auto random = getRandom(engine);
				while (('9' < random && random < 'A') || ('Z' < random && random < 'a')) {
					random = getRandom(engine);
				}
				c = random;
			}
			boundary[0] = boundary[1] = '-';
		}
		auto init() {
			generate_boundary();
			std::wstring value = L"multipart/form-data;boundary=";
			std::for_each(boundary.begin() + 2, boundary.end(), [&](auto& c) {
				value += c;
				});
			emplace(L"Content-Type", std::move(value));
		}
	public:
		Multipart(Header && header = {}):Data_Type(std::move(header)) {
			init();
		}
		auto add(std::string&& path) {
			const auto  name = std::move(std::filesystem::path(path).filename());
			body << boundary << "\r\nContent-Disposition: form-data;filename=" << name << "\r\n";
			std::ifstream file(path, std::ios::binary);
			std::copy(std::move_iterator(std::istreambuf_iterator<char>(file)), std::move_iterator(std::istreambuf_iterator<char>()), std::ostreambuf_iterator(body));
			body <<"\r\n" << boundary;
		}
		Multipart(std::string&& path,Header&& header = {}) :Data_Type(std::move(header)) {
			init();
			add(std::move(path));
		}
		Multipart(auto&&... path) {
			init();
			(add(std::move(path)),...);
		}
		std::string to_string_body() override{
			return std::move(body.str()+"--\r\n");
		}
	};

	export class Client {
	private:
		const URL url;
		const Handle session;
	public:
		Client(std::wstring&& url,std::wstring &&query_parameter=L"", std::wstring&& user_agent = L"") :
			url(std::move(url),std::move(query_parameter)),
			session(WinHttpOpen(user_agent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))
			
		{

		}
		template <methods method>
		auto request(Header&& header = {}, std::string body = {}) {
			return Request<method>(session, url, std::move(header.to_string()), std::move(body));
		}
		template <methods method>
		auto request(Header& header, std::string body = {}) {
			return Request<method>(session, url, std::move(header.to_string()), std::move(body));
		}

		template <methods method>
		auto request(Data_Type&& data) {
			return Request<method>(session, url, data.to_string_header(),data.to_string_body());
		}
	};

};