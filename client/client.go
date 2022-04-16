package client

import (
	"context"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"

	//"github.com/juju/persistent-cookiejar"
	"golang.org/x/net/publicsuffix"
)

type Cookie struct {
	Enabled  bool
	Filename string
	Jar      http.CookieJar
}

type Config struct {
	Scheme    string
	Host      string
	Port      int
	Path      string
	Cookie    Cookie
	Timeout   int
}

type ConfigUnix struct {
	Path   string
	Config Config
}

type BasicAuth struct {
	Username string
	Password string
}

type Request struct {
	UnixSocketPath string
	URL       string
	Headers   map[string]string
	BasicAuth BasicAuth
	Values    map[string][]string
	Cookie    Cookie
	Timeout   int
}

type Result struct {
	Response  *http.Response
	CookieJar http.CookieJar
	Body      []byte
	Error     error
}

var EmptyHeader = http.Header{}

var methods = []string{
	"OPTIONS",
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
}

func New(c *Config) (Request, error) {
	txtUrl := buildUrl(c)

	req := Request{
		URL:     txtUrl,
		Cookie:  c.Cookie,
		Timeout: c.Timeout,
	}

	return req, nil
}

func NewUnix(c *ConfigUnix) (Request, error) {
	txtUrl := buildUrl(&c.Config)

	return Request{
		UnixSocketPath: c.Path,
		URL:            txtUrl,
		Timeout:        c.Config.Timeout,
	}, nil
}

func (r *Request) HeaderAdd(name, value string) {
	if len(r.Headers) == 0 {
		r.Headers = make(map[string]string)
	}

	if _, ok := r.Headers[name]; !ok {
		r.Headers[name] = value
	}
}

func (r *Request) SetBasicAuth(username, password string) {
	ba := BasicAuth{
		Username: username,
		Password: password,
	}

	r.BasicAuth = ba
}

func (r *Request) ValueAdd(name, value string) {
	if len(r.Values) == 0 {
		r.Values = make(map[string][]string)
	}

	if _, ok := r.Values[name]; ok {
		r.Values[name] = append(r.Values[name], value)
	} else {
		r.Values[name] = []string{value}
	}
}

func (r *Request) Do(method string, data io.Reader) Result {
	clnt := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
    },
		Timeout: time.Second * time.Duration(r.Timeout),
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	if len(r.UnixSocketPath) > 0 {
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", r.UnixSocketPath)
		}
	}

	clnt.Transport = transport

	if r.Cookie.Enabled {
		if r.Cookie.Jar != nil {
			clnt.Jar = r.Cookie.Jar
		} else {
			options := cookiejar.Options{
				PublicSuffixList: publicsuffix.List,
				//Filename:         r.Cookie.Filename,
			}
			jar, err := cookiejar.New(&options)
			if err != err {
				return Result{Error: err}
			}

			clnt.Jar = jar
		}
	}

	req, err := http.NewRequest(method, r.URL, data)
	if err != nil {
		return Result{Error: err}
	}

	if len(r.Headers) > 0 {
		for key, value := range r.Headers {
			req.Header.Add(key, value)
		}
	}

	if r.BasicAuth != (BasicAuth{}) {
		req.SetBasicAuth(r.BasicAuth.Username, r.BasicAuth.Password)
	}

	if len(r.Values) > 0 {
		q := req.URL.Query()

		for k, values := range r.Values {
			for _, v := range values {
				q.Add(k, v)
			}
		}

		req.URL.RawQuery = q.Encode()
	}

	resp, err := clnt.Do(req)
	if err != nil {
		r := Result{Error: err}
		if resp != nil {
			r.Response = resp
		}

		return r
	}

	if method == "OPTIONS" || method == "HEAD" {
		return Result{Response: resp}
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Result{Response: resp, Error: err}
	}

	return Result{Response: resp, CookieJar: clnt.Jar, Body: body}
}

func (r *Request) Options() Result {
	return r.Do("OPTIONS", nil)
}

func (r *Request) Get() Result {
	return r.Do("GET", nil)
}

func (r *Request) Head() Result {
	return r.Do("HEAD", nil)
}

func (r *Request) Post(data io.Reader) Result {
	return r.Do("POST", data)
}

func (r *Request) Put(data io.Reader) Result {
	return r.Do("PUT", data)
}

func (r *Request) Delete() Result {
	return r.Do("DELETE", nil)
}
