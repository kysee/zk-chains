## Event Structure

### Abstract

Hyperledger Fabric (HLF) 은 트랜잭션에 오직 하나의 이벤트만이 포함될 수 있도록 구현되어,
다수의 이벤트 발생이 가능한 다른 체인에 비하여 이벤트를 이용한 작업에 많은 한계를 갖는다.
이에 자체적인 이벤트 구조를 정의하고 이를 하나의 바이트 스트림으로 인코딩하여 HLF 이벤트로 기록하고, 
이 값을 다시 디코딩하여 정의된 이밴트 구조를 활용한 다양한 기능 구현이 가능하도록 한다.

### EventLog

```go
type EventLog struct {
    Type  string `json:"type"`
    Value []byte `json:"value"`
}
```

체인코드에서 필요한 이벤트 구조를 정의하고 이를 인코딩한 값을 `Value` 에 기록한다.
이 때 `Type` 은 `Value` 에 기록된 바이트 스트림이 어떤 타입의 데이터 구조를 인코딩한 것인지 식별하기 위한 것인데, 
디코딩시 디코딩할 데이터 구조를 정하기 위해 반드시 필요하다.

체인코드에서 이벤트 구조의 정의와 인코딩/디코딩 예시는 `post_mesage.go` 파일의 `PostMessageEventLogValue` 를 참조한다.

### EventPayload

```go
type EventPayload struct {
    Logs []*EventLog
}
```

다수의 `EventLog` 는 하나의 `EventPayload` 를 구성한다.
그리고 `EventPayload` 를 바이트 스트림으로 인코딩한 값이 실제 트랜잭션에 기록될 이벤트 내용이 된다.

### Event Name

체인코드에서 이벤트 기록을 위해 `SetEvent` 를 호출할 때 지정되는 이벤트 이름은 
클라이언트 측에서 이벤트 필터링을 할 때 정규표현식 매칭 대상으로 사용된다.  
EventPayload 의 인코딩 값을 이벤트 내용으로 기록할 때, EventPayload 에 포함된 모든 EventLog.Type,
또는 그와 일대일 대응되는 로그 이름을 임의의 구분자로 연결하여 최종적으로 '이벤트 이름' 을 구성하도록 한다면, 
클라이언트는 이를 통해 특정 EventLog 포함여부를 정규표현식 구성을 통해 필터링 할 수 있을 것이다.

다음은 체인코드에서 구조화된 이벤트 `AEventLogValue`, `BEventLogValue` 를 정의하고 이를 HFL 이벤트로 기록하는 샘플 코드이다.

```go
type AEventLogValue struct {...}
type BEventLogValue struct {...}

jzA, _ := json.Marshal(&AEventLogValue{})
jzB, _ := json.Marshal(&BEventLogValue{})

eventPayload := &EventPayload{
	Logs: []*EventLog{
		{Type: "AEventLogValue", Value: jzA},
        {Type: "BEventLogValue", Value: jzB},
	},
}

jzPayload, _ := json.Marshal(eventPayload)
SetEvent("AEvent,BEvent", jzPayload)

```