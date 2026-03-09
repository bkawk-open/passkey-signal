package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var tableName = os.Getenv("DYNAMODB_TABLE")

// Users

func getUser(ctx context.Context, db *dynamodb.Client, phone string) (*UserItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item UserItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func putUser(ctx context.Context, db *dynamodb.Client, item UserItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

// Credentials

func getUserCredentials(ctx context.Context, db *dynamodb.Client, phone string) ([]CredentialItem, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + phone},
			":sk": &types.AttributeValueMemberS{Value: "CRED#"},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []CredentialItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func putCredential(ctx context.Context, db *dynamodb.Client, item CredentialItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func updateCredentialSignCount(ctx context.Context, db *dynamodb.Client, phone string, credID string, signCount uint32) error {
	_, err := db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "CRED#" + credID},
		},
		UpdateExpression: aws.String("SET SignCount = :sc"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":sc": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", signCount)},
		},
	})
	return err
}

func deleteCredential(ctx context.Context, db *dynamodb.Client, phone string, credID string) error {
	_, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "CRED#" + credID},
		},
	})
	return err
}

// Wrapped Keys

func putWrappedKey(ctx context.Context, db *dynamodb.Client, item WrappedKeyItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getWrappedKey(ctx context.Context, db *dynamodb.Client, phone string, credID string) (*WrappedKeyItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "WRAPKEY#" + credID},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item WrappedKeyItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func deleteWrappedKey(ctx context.Context, db *dynamodb.Client, phone string, credID string) error {
	_, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "WRAPKEY#" + credID},
		},
	})
	return err
}

func getUserWrappedKeys(ctx context.Context, db *dynamodb.Client, phone string) ([]WrappedKeyItem, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + phone},
			":sk": &types.AttributeValueMemberS{Value: "WRAPKEY#"},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []WrappedKeyItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// Sessions

func putSession(ctx context.Context, db *dynamodb.Client, item SessionItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getSession(ctx context.Context, db *dynamodb.Client, challengeID string) (*SessionItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "SESSION#" + challengeID},
			"SK": &types.AttributeValueMemberS{Value: "CHALLENGE"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item SessionItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func deleteSession(ctx context.Context, db *dynamodb.Client, challengeID string) error {
	_, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "SESSION#" + challengeID},
			"SK": &types.AttributeValueMemberS{Value: "CHALLENGE"},
		},
	})
	return err
}

// consumeSession atomically deletes and returns a session.
// Returns nil if the session does not exist (already consumed or never created).
func consumeSession(ctx context.Context, db *dynamodb.Client, challengeID string) (*SessionItem, error) {
	out, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "SESSION#" + challengeID},
			"SK": &types.AttributeValueMemberS{Value: "CHALLENGE"},
		},
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ReturnValues:        types.ReturnValueAllOld,
	})
	if err != nil {
		// ConditionalCheckFailedException means session was already consumed
		var condErr *types.ConditionalCheckFailedException
		if ok := errors.As(err, &condErr); ok {
			return nil, nil
		}
		return nil, err
	}
	if out.Attributes == nil {
		return nil, nil
	}
	var item SessionItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

// Tokens

func putToken(ctx context.Context, db *dynamodb.Client, item TokenItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getToken(ctx context.Context, db *dynamodb.Client, token string) (*TokenItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "TOKEN#" + token},
			"SK": &types.AttributeValueMemberS{Value: "AUTH"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item TokenItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func deleteToken(ctx context.Context, db *dynamodb.Client, token string) error {
	_, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "TOKEN#" + token},
			"SK": &types.AttributeValueMemberS{Value: "AUTH"},
		},
	})
	return err
}

// Notes

func getNote(ctx context.Context, db *dynamodb.Client, phone string) (*NoteItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "NOTE"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item NoteItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func putNote(ctx context.Context, db *dynamodb.Client, item NoteItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

// Invitations

func putInviteWithUserLink(ctx context.Context, db *dynamodb.Client, invite InviteItem) error {
	inviteAV, err := attributevalue.MarshalMap(invite)
	if err != nil {
		return err
	}
	linkAV, err := attributevalue.MarshalMap(InviteLinkItem{
		PK:       "USER#" + invite.Phone,
		SK:       "INVITE#" + invite.InviteID,
		InviteID: invite.InviteID,
		TTL:      invite.TTL,
	})
	if err != nil {
		return err
	}
	_, err = db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: &tableName, Item: inviteAV}},
			{Put: &types.Put{TableName: &tableName, Item: linkAV}},
		},
	})
	return err
}

func getInvite(ctx context.Context, db *dynamodb.Client, inviteID string) (*InviteItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "INVITE#" + inviteID},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item InviteItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func updateInviteStatus(ctx context.Context, db *dynamodb.Client, inviteID string, fromStatus string, toStatus string) error {
	_, err := db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "INVITE#" + inviteID},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
		UpdateExpression:    aws.String("SET #s = :new"),
		ConditionExpression: aws.String("#s = :old"),
		ExpressionAttributeNames: map[string]string{
			"#s": "Status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":old": &types.AttributeValueMemberS{Value: fromStatus},
			":new": &types.AttributeValueMemberS{Value: toStatus},
		},
	})
	return err
}

func countActiveInvites(ctx context.Context, db *dynamodb.Client, phone string) (int, error) {
	now := time.Now().Unix()
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		FilterExpression:       aws.String("#ttl > :now"),
		ExpressionAttributeNames: map[string]string{
			"#ttl": "TTL",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":  &types.AttributeValueMemberS{Value: "USER#" + phone},
			":sk":  &types.AttributeValueMemberS{Value: "INVITE#"},
			":now": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
		},
		Select: types.SelectCount,
	})
	if err != nil {
		return 0, err
	}
	return int(out.Count), nil
}

// GSI query: find user by UserID (for discoverable login)

func getUserByUserID(ctx context.Context, db *dynamodb.Client, userID string) (*UserItem, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		IndexName:              aws.String("UserID-index"),
		KeyConditionExpression: aws.String("UserID = :uid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":uid": &types.AttributeValueMemberS{Value: userID},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Items) == 0 {
		return nil, nil
	}
	// Filter for PROFILE items (GSI projects all, may include CRED items)
	for _, item := range out.Items {
		var u UserItem
		if err := attributevalue.UnmarshalMap(item, &u); err != nil {
			continue
		}
		if u.SK == "PROFILE" {
			return &u, nil
		}
	}
	return nil, nil
}

// OTP

func putOTP(ctx context.Context, db *dynamodb.Client, item OTPItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

// consumeOTP atomically deletes and returns an OTP.
// Returns nil if the OTP does not exist (already consumed or never created).
func consumeOTP(ctx context.Context, db *dynamodb.Client, otpID string) (*OTPItem, error) {
	out, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "OTP#" + otpID},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ReturnValues:        types.ReturnValueAllOld,
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if ok := errors.As(err, &condErr); ok {
			return nil, nil
		}
		return nil, err
	}
	if out.Attributes == nil {
		return nil, nil
	}
	var item OTPItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

// Rate Limiting

func putRateLimit(ctx context.Context, db *dynamodb.Client, item RateLimitItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func countRecentOTPs(ctx context.Context, db *dynamodb.Client, phone string) (int, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "RATE#" + phone},
			":sk": &types.AttributeValueMemberS{Value: "SMS#"},
		},
		Select: types.SelectCount,
	})
	if err != nil {
		return 0, err
	}
	return int(out.Count), nil
}

// Device Enrolment

func putEnrolToken(ctx context.Context, db *dynamodb.Client, item EnrolTokenItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getEnrolToken(ctx context.Context, db *dynamodb.Client, token string) (*EnrolTokenItem, error) {
	out, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "ENROL#" + token},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var item EnrolTokenItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func getEnrolTokenByEnrolId(ctx context.Context, db *dynamodb.Client, enrolId string) (*EnrolTokenItem, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		IndexName:              aws.String("EnrolId-index"),
		KeyConditionExpression: aws.String("EnrolId = :eid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":eid": &types.AttributeValueMemberS{Value: enrolId},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Items) == 0 {
		return nil, nil
	}
	var item EnrolTokenItem
	if err := attributevalue.UnmarshalMap(out.Items[0], &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func updateEnrolTokenStatus(ctx context.Context, db *dynamodb.Client, pk string, fromStatus string, toStatus string, extra map[string]types.AttributeValue) error {
	updateExpr := "SET #s = :new"
	exprNames := map[string]string{"#s": "Status"}
	exprValues := map[string]types.AttributeValue{
		":old": &types.AttributeValueMemberS{Value: fromStatus},
		":new": &types.AttributeValueMemberS{Value: toStatus},
	}

	for k, v := range extra {
		updateExpr += ", " + k + " = :" + k
		exprValues[":"+k] = v
	}

	_, err := db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
		UpdateExpression:    aws.String(updateExpr),
		ConditionExpression: aws.String("#s = :old"),
		ExpressionAttributeNames:  exprNames,
		ExpressionAttributeValues: exprValues,
	})
	return err
}

func putDevice(ctx context.Context, db *dynamodb.Client, item DeviceItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getDeviceByDeviceId(ctx context.Context, db *dynamodb.Client, deviceId string) (*DeviceItem, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		IndexName:              aws.String("DeviceId-index"),
		KeyConditionExpression: aws.String("DeviceId = :did"),
		FilterExpression:       aws.String("begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":did": &types.AttributeValueMemberS{Value: deviceId},
			":sk":  &types.AttributeValueMemberS{Value: "DEVICE#"},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Items) == 0 {
		return nil, nil
	}
	var item DeviceItem
	if err := attributevalue.UnmarshalMap(out.Items[0], &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func getUserDevices(ctx context.Context, db *dynamodb.Client, phone string) ([]DeviceItem, error) {
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + phone},
			":sk": &types.AttributeValueMemberS{Value: "DEVICE#"},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []DeviceItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func deleteDevice(ctx context.Context, db *dynamodb.Client, phone string, deviceId string) error {
	_, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + phone},
			"SK": &types.AttributeValueMemberS{Value: "DEVICE#" + deviceId},
		},
	})
	return err
}

func putDeviceChallenge(ctx context.Context, db *dynamodb.Client, item DeviceChallengeItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func consumeDeviceChallenge(ctx context.Context, db *dynamodb.Client, challengeId string) (*DeviceChallengeItem, error) {
	out, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "DEVCHALLENGE#" + challengeId},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ReturnValues:        types.ReturnValueAllOld,
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if ok := errors.As(err, &condErr); ok {
			return nil, nil
		}
		return nil, err
	}
	if out.Attributes == nil {
		return nil, nil
	}
	var item DeviceChallengeItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func putDKGSession(ctx context.Context, db *dynamodb.Client, item DKGSessionItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getDKGSession(ctx context.Context, db *dynamodb.Client, sessionID string) (*DKGSessionItem, error) {
	result, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "DKG#" + sessionID},
			"SK": &types.AttributeValueMemberS{Value: "SESSION"},
		},
	})
	if err != nil {
		return nil, err
	}
	if result.Item == nil {
		return nil, nil
	}
	var item DKGSessionItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func putWallet(ctx context.Context, db *dynamodb.Client, item WalletItem) error {
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}
	_, err = db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      av,
	})
	return err
}

func getWallet(ctx context.Context, db *dynamodb.Client, jointPubKey string) (*WalletItem, error) {
	result, err := db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "WALLET#" + jointPubKey},
			"SK": &types.AttributeValueMemberS{Value: "DATA"},
		},
	})
	if err != nil {
		return nil, err
	}
	if result.Item == nil {
		return nil, nil
	}
	var item WalletItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func getWalletByUserID(ctx context.Context, db *dynamodb.Client, userID string) (*WalletItem, error) {
	result, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &tableName,
		IndexName:              stringPtr("UserID-index"),
		KeyConditionExpression: stringPtr("UserID = :uid"),
		FilterExpression:       stringPtr("begins_with(PK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":uid":    &types.AttributeValueMemberS{Value: userID},
			":prefix": &types.AttributeValueMemberS{Value: "WALLET#"},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(result.Items) == 0 {
		return nil, nil
	}
	var item WalletItem
	if err := attributevalue.UnmarshalMap(result.Items[0], &item); err != nil {
		return nil, err
	}
	return &item, nil
}

