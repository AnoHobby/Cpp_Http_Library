#include <Windows.h>
#include <winhttp.h>
#include <string>
#pragma comment(lib, "winhttp.lib")
export module http;
namespace http {
	export class URL {
	private:
		//const•t‚¯‚ê‚½‚ç•t‚¯‚æ‚¤
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
	export class HttpClient {
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
		class Request {
		private:
			const Handle request;
		public:
			Request(const methods method, const Handle& connect, const URL& url, std::wstring&& header = L"", std::wstring&& data = L"") :
				request(
					WinHttpOpenRequest(
						connect.get(),
						[&method]() {
							switch (method) {
							case methods::GET:
								return L"GET";
							case methods::POST:
								return L"POST";
							}
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
					data.data(),
					data.size(),
					data.size(),
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
		HttpClient(std::wstring&& url) :
			url(std::move(url)),
			session(WinHttpOpen(L"UserAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)),
			connect(WinHttpConnect(session.get(), this->url.get_host_name().c_str(), this->url.get_port(), 0))
		{

		}
		auto request(methods method, std::wstring&& header = L"", std::wstring&& data = L"") {
			return Request(method, connect, url, std::move(header), std::move(data));
		}
	};

};